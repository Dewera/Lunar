using System.ComponentModel;
using System.Diagnostics;
using System.Numerics;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Lunar.Extensions;
using Lunar.FileResolution;
using Lunar.Helpers;
using Lunar.Native;
using Lunar.Native.Enums;
using Lunar.Native.PInvoke;
using Lunar.Native.Structs;
using Lunar.PortableExecutable;
using Lunar.Remote;

namespace Lunar;

/// <summary>
/// Provides the functionality to map a DLL from disk or memory into a process
/// </summary>
public sealed class LibraryMapper
{
    /// <summary>
    /// The base address of the DLL in the process
    /// </summary>
    public nint DllBaseAddress { get; private set; }

    private readonly Memory<byte> _dllBytes;
    private readonly FileResolver _fileResolver;
    private nint _ldrEntryAddress;
    private readonly MappingFlags _mappingFlags;
    private readonly PeImage _peImage;
    private readonly ProcessContext _processContext;

    /// <summary>
    /// Initialises an instances of the <see cref="LibraryMapper"/> class with the functionality to map a DLL from memory into a process
    /// </summary>
    public LibraryMapper(Process process, Memory<byte> dllBytes, MappingFlags mappingFlags = MappingFlags.None)
    {
        if (process.HasExited)
        {
            throw new ArgumentException("The provided process is not currently running");
        }

        if (dllBytes.IsEmpty)
        {
            throw new ArgumentException("The provided DLL bytes were empty");
        }

        if (!Environment.Is64BitProcess && process.GetArchitecture() == Architecture.X64)
        {
            throw new NotSupportedException("The provided process cannot be mapped into from an x86 build");
        }

        _dllBytes = dllBytes.ToArray();
        _fileResolver = new FileResolver(process, null);
        _mappingFlags = mappingFlags;
        _peImage = new PeImage(dllBytes);
        _processContext = new ProcessContext(process);
    }

    /// <summary>
    /// Initialises an instances of the <see cref="LibraryMapper"/> class with the functionality to map a DLL from disk into a process
    /// </summary>
    public LibraryMapper(Process process, string dllFilePath, MappingFlags mappingFlags = MappingFlags.None)
    {
        if (process.HasExited)
        {
            throw new ArgumentException("The provided process is not currently running");
        }

        if (!File.Exists(dllFilePath))
        {
            throw new ArgumentException("The provided file path did not point to a valid file");
        }

        if (!Environment.Is64BitProcess && process.GetArchitecture() == Architecture.X64)
        {
            throw new NotSupportedException("The provided process cannot be mapped into from an x86 build");
        }

        var dllBytes = File.ReadAllBytes(dllFilePath);

        _dllBytes = dllBytes.ToArray();
        _fileResolver = new FileResolver(process, Path.GetDirectoryName(dllFilePath));
        _mappingFlags = mappingFlags;
        _peImage = new PeImage(dllBytes);
        _processContext = new ProcessContext(process);
    }

    /// <summary>
    /// Maps the DLL into the process
    /// </summary>
    public void MapLibrary()
    {
        if (DllBaseAddress != 0)
        {
            return;
        }

        var cleanupStack = new Stack<Action>();

        try
        {
            AllocateImage();
            cleanupStack.Push(FreeImage);

            AllocateLoaderEntry();
            cleanupStack.Push(FreeLoaderEntry);

            LoadDependencies();
            cleanupStack.Push(FreeDependencies);

            BuildImportAddressTable();
            RelocateImage();
            MapHeaders();
            MapSections();
            InitialiseControlFlowGuard();
            InitialiseSecurityCookie();

            InsertExceptionHandlers();
            cleanupStack.Push(RemoveExceptionHandlers);

            InitialiseTlsData();
            cleanupStack.Push(RemoveTlsData);

            CallInitialisationRoutines(DllReason.ProcessAttach);
        }
        catch
        {
            while (cleanupStack.TryPop(out var cleanupRoutine))
            {
                Executor.IgnoreExceptions(cleanupRoutine);
            }

            throw;
        }
    }

    /// <summary>
    /// Unmaps the DLL from the process
    /// </summary>
    public void UnmapLibrary()
    {
        if (DllBaseAddress == 0)
        {
            return;
        }

        var topLevelException = default(Exception);

        try
        {
            CallInitialisationRoutines(DllReason.ProcessDetach);
        }
        catch (Exception exception)
        {
            topLevelException ??= exception;
        }

        try
        {
            RemoveTlsData();
        }
        catch (Exception exception)
        {
            topLevelException ??= exception;
        }

        try
        {
            RemoveExceptionHandlers();
        }
        catch (Exception exception)
        {
            topLevelException ??= exception;
        }

        try
        {
            FreeDependencies();
        }
        catch (Exception exception)
        {
            topLevelException ??= exception;
        }

        try
        {
            FreeImage();
        }
        catch (Exception exception)
        {
            topLevelException ??= exception;
        }

        try
        {
            FreeLoaderEntry();
        }
        catch (Exception exception)
        {
            topLevelException ??= exception;
        }

        if (topLevelException is not null)
        {
            throw topLevelException;
        }
    }

    private void AllocateImage()
    {
        DllBaseAddress = _processContext.Process.AllocateBuffer(_peImage.Headers.PEHeader!.SizeOfImage, ProtectionType.ReadOnly);
    }

    private void AllocateLoaderEntry()
    {
        if (_processContext.Architecture == Architecture.X86)
        {
            _ldrEntryAddress = _processContext.Process.AllocateBuffer(Unsafe.SizeOf<LdrDataTableEntry32>(), ProtectionType.ReadWrite);
            var loaderEntry = new LdrDataTableEntry32 { DllBase = (int) DllBaseAddress };
            _processContext.Process.WriteStruct(_ldrEntryAddress, loaderEntry);
        }
        else
        {
            _ldrEntryAddress = _processContext.Process.AllocateBuffer(Unsafe.SizeOf<LdrDataTableEntry64>(), ProtectionType.ReadWrite);
            var loaderEntry = new LdrDataTableEntry64 { DllBase = DllBaseAddress };
            _processContext.Process.WriteStruct(_ldrEntryAddress, loaderEntry);
        }
    }

    private void BuildImportAddressTable()
    {
        Parallel.ForEach(_peImage.ImportDirectory.GetImportDescriptors(), importDescriptor =>
        {
            foreach (var (functionName, functionOffset, functionOrdinal) in importDescriptor.Functions)
            {
                // Write the function address into the import address table

                var functionAddress = functionName is null ? _processContext.GetFunctionAddress(importDescriptor.Name, functionOrdinal) : _processContext.GetFunctionAddress(importDescriptor.Name, functionName);
                MemoryMarshal.Write(_dllBytes.Span[functionOffset..], ref functionAddress);
            }
        });
    }

    private void CallInitialisationRoutines(DllReason reason)
    {
        if (_mappingFlags.HasFlag(MappingFlags.SkipInitRoutines))
        {
            return;
        }

        // Call the entry point of any TLS callbacks

        foreach (var callbackAddress in _peImage.TlsDirectory.GetTlsCallbacks().Select(callBack => DllBaseAddress + callBack.RelativeAddress))
        {
            _processContext.CallRoutine(callbackAddress, CallingConvention.StdCall, DllBaseAddress, reason, 0);
        }

        if ((_peImage.Headers.CorHeader?.Flags.HasFlag(CorFlags.ILOnly) ?? false) || _peImage.Headers.PEHeader!.AddressOfEntryPoint == 0)
        {
            return;
        }

        // Call the DLL entry point

        var entryPointAddress = DllBaseAddress + _peImage.Headers.PEHeader!.AddressOfEntryPoint;

        if (!_processContext.CallRoutine<bool>(entryPointAddress, CallingConvention.StdCall, DllBaseAddress, reason, 0))
        {
            throw new ApplicationException($"Failed to call the DLL entry point with {reason:G}");
        }
    }

    private void FreeDependencies()
    {
        foreach (var (_, dependencyName) in _peImage.ImportDirectory.GetImportDescriptors())
        {
            // Free the dependency using the Windows loader

            var dependencyAddress = _processContext.GetModuleAddress(dependencyName);

            if (!_processContext.CallRoutine<bool>(_processContext.GetFunctionAddress("kernel32.dll", "FreeLibrary"), CallingConvention.StdCall, dependencyAddress))
            {
                throw new ApplicationException($"Failed to free the dependency {dependencyName} from the process");
            }
        }

        _processContext.ClearModuleCache();
    }

    private void FreeImage()
    {
        try
        {
            _processContext.Process.FreeBuffer(DllBaseAddress);
        }
        finally
        {
            DllBaseAddress = 0;
        }
    }

    private void FreeLoaderEntry()
    {
        try
        {
            _processContext.Process.FreeBuffer(_ldrEntryAddress);
        }
        finally
        {
            _ldrEntryAddress = 0;
        }
    }

    private void InitialiseControlFlowGuard()
    {
        var loadConfigData = _peImage.LoadConfigDirectory.GetLoadConfigData();

        if (loadConfigData is null || !loadConfigData.GuardFlags.HasFlag(GuardFlags.Instrumented))
        {
            return;
        }

        // Check if the process is using control flow guard

        if (!_processContext.CallRoutine<bool>(_processContext.GetFunctionAddress("ntdll.dll", "LdrControlFlowGuardEnforced"), CallingConvention.StdCall))
        {
            return;
        }

        // Check if the process is using export suppression

        var usingExportSuppression = false;

        if (loadConfigData.GuardFlags.HasFlag(GuardFlags.ExportSuppressionInfoPresent))
        {
            usingExportSuppression = _processContext.CallRoutine<bool>(_processContext.GetNtdllSymbolAddress("LdrControlFlowGuardEnforcedWithExportSuppression"), CallingConvention.StdCall);
        }

        var checkFunctionName = "LdrpValidateUserCallTarget";
        var dispatchFunctionName = "LdrpDispatchUserCallTarget";

        if (usingExportSuppression)
        {
            checkFunctionName = $"{checkFunctionName}ES";
            dispatchFunctionName = $"{dispatchFunctionName}ES";
        }

        var loadConfigDirectoryAddress = DllBaseAddress + _peImage.Headers.PEHeader!.LoadConfigTableDirectory.RelativeVirtualAddress;

        if (_processContext.Architecture == Architecture.X86)
        {
            // Update the check function pointer

            var loadConfigDirectory = _processContext.Process.ReadStruct<ImageLoadConfigDirectory32>(loadConfigDirectoryAddress);
            _processContext.Process.WriteStruct(loadConfigDirectoryAddress, loadConfigDirectory with { GuardCfCheckFunctionPointer = (int) _processContext.GetNtdllSymbolAddress(checkFunctionName) });
        }
        else
        {
            // Update the check and dispatch function pointers

            var loadConfigDirectory = _processContext.Process.ReadStruct<ImageLoadConfigDirectory64>(loadConfigDirectoryAddress);
            _processContext.Process.WriteStruct(loadConfigDirectoryAddress, loadConfigDirectory with { GuardCfCheckFunctionPointer = _processContext.GetNtdllSymbolAddress(checkFunctionName), GuardCfDispatchFunctionPointer = _processContext.GetNtdllSymbolAddress(dispatchFunctionName) });
        }
    }

    private void InitialiseSecurityCookie()
    {
        var loadConfigData = _peImage.LoadConfigDirectory.GetLoadConfigData();

        if (loadConfigData?.SecurityCookie is null || loadConfigData.GuardFlags.HasFlag(GuardFlags.SecurityCookieUnused))
        {
            return;
        }

        // Generate a randomised security cookie

        var securityCookieBytes = _processContext.Architecture == Architecture.X86 ? stackalloc byte[4] : stackalloc byte[6];
        RandomNumberGenerator.Fill(securityCookieBytes);

        // Ensure the default security cookie was not generated

        if (securityCookieBytes is [0xBB, 0x40, 0xE6, 0x4E] or [0x2B, 0x99, 0x2D, 0xDF, 0xA2, 0x32])
        {
            securityCookieBytes[^1] += 1;
        }

        // Initialise the security cookie

        var securityCookieAddress = DllBaseAddress + loadConfigData.SecurityCookie.RelativeAddress;
        _processContext.Process.WriteSpan(securityCookieAddress, securityCookieBytes);
    }

    private void InitialiseTlsData()
    {
        if (_peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.Size == 0)
        {
            return;
        }

        var status = _processContext.CallRoutine<NtStatus>(_processContext.GetNtdllSymbolAddress("LdrpHandleTlsData"), CallingConvention.FastCall, _ldrEntryAddress);

        if (!status.IsSuccess())
        {
            throw new Win32Exception(Ntdll.RtlNtStatusToDosError(status));
        }
    }

    private void InsertExceptionHandlers()
    {
        nint functionTableAddress;

        if (_processContext.Architecture == Architecture.X86)
        {
            try
            {
                functionTableAddress = _processContext.GetNtdllSymbolAddress("LdrpInvertedFunctionTables");
            }
            catch
            {
                functionTableAddress = _processContext.GetNtdllSymbolAddress("LdrpInvertedFunctionTable");
            }
        }
        else
        {
            functionTableAddress = _processContext.GetFunctionAddress("ntdll.dll", "KiUserInvertedFunctionTable");
        }

        using var pebLock = new PebLock(_processContext);

        // Read the function table

        var functionTable = _processContext.Process.ReadStruct<InvertedFunctionTable>(functionTableAddress);

        if (functionTable.Overflow)
        {
            return;
        }

        if (functionTable.CurrentSize == functionTable.MaximumSize)
        {
            // Mark the function table as overflowed

            functionTable = functionTable with { Overflow = true };
            _processContext.Process.WriteStruct(functionTableAddress, functionTable);
        }
        else
        {
            if (_processContext.Architecture == Architecture.X86)
            {
                var loadConfigData = _peImage.LoadConfigDirectory.GetLoadConfigData();

                if (loadConfigData is null)
                {
                    return;
                }

                // Read the function table entry list

                var functionTableEntryListAddress = functionTableAddress + Unsafe.SizeOf<InvertedFunctionTable>();
                var functionTableEntryList = _processContext.Process.ReadSpan<InvertedFunctionTableEntry32>(functionTableEntryListAddress, Constants.InvertedFunctionTableSize);

                // Search for a free index to insert the entry

                var insertionIndex = 1;

                while (insertionIndex < functionTable.CurrentSize)
                {
                    if ((uint) DllBaseAddress < (uint) functionTableEntryList[insertionIndex].ImageBase)
                    {
                        break;
                    }

                    insertionIndex += 1;
                }

                if (insertionIndex < functionTable.CurrentSize)
                {
                    // Shift the existing elements to make space for the entry

                    for (var entryIndex = functionTable.CurrentSize - 1; entryIndex >= insertionIndex; entryIndex -= 1)
                    {
                        functionTableEntryList[entryIndex + 1] = functionTableEntryList[entryIndex];
                    }
                }

                // Encode the exception directory address using the system pointer encoding algorithm

                var sharedUserData = _processContext.Process.ReadStruct<KUserSharedData>(Constants.SharedUserDataAddress);
                var exceptionDirectoryAddress = DllBaseAddress + loadConfigData.ExceptionTable!.RelativeAddress;
                var rotateValue = sharedUserData.Cookie & 0x1F;
                var encodedAddress = BitOperations.RotateRight((uint) exceptionDirectoryAddress ^ (uint) sharedUserData.Cookie, rotateValue);

                // Update the function table entry list

                functionTableEntryList[insertionIndex] = new InvertedFunctionTableEntry32((int) encodedAddress, (int) DllBaseAddress, _peImage.Headers.PEHeader!.SizeOfImage, loadConfigData.ExceptionTable!.HandlerCount);
                _processContext.Process.WriteSpan(functionTableEntryListAddress, functionTableEntryList);
            }
            else
            {
                // Read the function table entry list

                var functionTableEntryListAddress = functionTableAddress + Unsafe.SizeOf<InvertedFunctionTable>();
                var functionTableEntryList = _processContext.Process.ReadSpan<InvertedFunctionTableEntry64>(functionTableEntryListAddress, Constants.InvertedFunctionTableSize);

                // Search for a free index to insert the entry

                var insertionIndex = 1;

                while (insertionIndex < functionTable.CurrentSize)
                {
                    if ((ulong) DllBaseAddress < (ulong) functionTableEntryList[insertionIndex].ImageBase)
                    {
                        break;
                    }

                    insertionIndex += 1;
                }

                if (insertionIndex < functionTable.CurrentSize)
                {
                    // Shift the existing elements to make space for the entry

                    for (var entryIndex = functionTable.CurrentSize - 1; entryIndex >= insertionIndex; entryIndex -= 1)
                    {
                        functionTableEntryList[entryIndex + 1] = functionTableEntryList[entryIndex];
                    }
                }

                // Update the function table entry list

                var exceptionDirectoryAddress = DllBaseAddress + _peImage.Headers.PEHeader!.ExceptionTableDirectory.RelativeVirtualAddress;
                functionTableEntryList[insertionIndex] = new InvertedFunctionTableEntry64(exceptionDirectoryAddress, DllBaseAddress, _peImage.Headers.PEHeader!.SizeOfImage, _peImage.Headers.PEHeader!.ExceptionTableDirectory.Size);
                _processContext.Process.WriteSpan(functionTableEntryListAddress, functionTableEntryList);
            }

            // Update the function table

            functionTable = functionTable with { CurrentSize = functionTable.CurrentSize + 1 };
            _processContext.Process.WriteStruct(functionTableAddress, functionTable);
        }
    }

    private void LoadDependencies()
    {
        var activationContext = new ActivationContext(_peImage.ResourceDirectory.GetManifest(), _processContext.Architecture);

        foreach (var (_, dependencyName) in _peImage.ImportDirectory.GetImportDescriptors())
        {
            // Write the dependency file path into the process

            var dependencyFilePath = _fileResolver.ResolveFilePath(_processContext.ResolveModuleName(dependencyName, null), activationContext);

            if (dependencyFilePath is null)
            {
                throw new FileNotFoundException($"Failed to resolve the dependency file path for {dependencyName}");
            }

            var dependencyFilePathAddress = _processContext.Process.AllocateBuffer(Encoding.Unicode.GetByteCount(dependencyFilePath), ProtectionType.ReadOnly);

            try
            {
                _processContext.Process.WriteString(dependencyFilePathAddress, dependencyFilePath);

                // Load the dependency using the Windows loader

                var dependencyAddress = _processContext.CallRoutine<nint>(_processContext.GetFunctionAddress("kernel32.dll", "LoadLibraryW"), CallingConvention.StdCall, dependencyFilePathAddress);

                if (dependencyAddress == 0)
                {
                    throw new ApplicationException($"Failed to load the dependency {dependencyName} into the process");
                }

                _processContext.RecordModuleLoad(dependencyAddress, dependencyFilePath);
            }
            finally
            {
                Executor.IgnoreExceptions(() => _processContext.Process.FreeBuffer(dependencyFilePathAddress));
            }
        }
    }

    private void MapHeaders()
    {
        if (_mappingFlags.HasFlag(MappingFlags.DiscardHeaders))
        {
            return;
        }

        var headerBytes = _dllBytes.Span[.._peImage.Headers.PEHeader!.SizeOfHeaders];
        _processContext.Process.WriteSpan(DllBaseAddress, headerBytes);
    }

    private void MapSections()
    {
        var sectionHeaders = _peImage.Headers.SectionHeaders.AsEnumerable();

        if (_peImage.Headers.CorHeader is null || !_peImage.Headers.CorHeader.Flags.HasFlag(CorFlags.ILOnly))
        {
            sectionHeaders = sectionHeaders.Where(sectionHeader => !sectionHeader.SectionCharacteristics.HasFlag(SectionCharacteristics.MemDiscardable));
        }

        foreach (var sectionHeader in sectionHeaders)
        {
            if (sectionHeader.SizeOfRawData == 0)
            {
                continue;
            }

            // Map the raw section

            var sectionAddress = DllBaseAddress + sectionHeader.VirtualAddress;
            var sectionBytes = _dllBytes.Span.Slice(sectionHeader.PointerToRawData, sectionHeader.SizeOfRawData);
            _processContext.Process.WriteSpan(sectionAddress, sectionBytes);

            // Determine the protection to apply to the section

            ProtectionType sectionProtection;

            if (sectionHeader.SectionCharacteristics.HasFlag(SectionCharacteristics.MemExecute))
            {
                if (sectionHeader.SectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                {
                    sectionProtection = sectionHeader.SectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ExecuteReadWrite : ProtectionType.ExecuteWriteCopy;
                }
                else
                {
                    sectionProtection = sectionHeader.SectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ExecuteRead : ProtectionType.Execute;
                }
            }
            else if (sectionHeader.SectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
            {
                sectionProtection = sectionHeader.SectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ReadWrite : ProtectionType.WriteCopy;
            }
            else
            {
                sectionProtection = sectionHeader.SectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ReadOnly : ProtectionType.NoAccess;
            }

            if (sectionHeader.SectionCharacteristics.HasFlag(SectionCharacteristics.MemNotCached))
            {
                sectionProtection |= ProtectionType.NoCache;
            }

            // Calculate the aligned section size

            var sectionAlignment = _peImage.Headers.PEHeader!.SectionAlignment;
            var alignedSectionSize = Math.Max(sectionHeader.SizeOfRawData, sectionHeader.VirtualSize);
            alignedSectionSize = alignedSectionSize + sectionAlignment - 1 - (alignedSectionSize + sectionAlignment - 1) % sectionAlignment;

            // Adjust the protection of the aligned section

            _processContext.Process.ProtectBuffer(sectionAddress, alignedSectionSize, sectionProtection);
        }
    }

    private void RelocateImage()
    {
        if (_processContext.Architecture == Architecture.X86)
        {
            // Calculate the delta from the preferred base address

            var delta = (uint) DllBaseAddress - (uint) _peImage.Headers.PEHeader!.ImageBase;

            Parallel.ForEach(_peImage.RelocationDirectory.GetRelocations(), relocation =>
            {
                if (relocation.Type != RelocationType.HighLow)
                {
                    return;
                }

                // Perform the relocation

                var relocationValue = MemoryMarshal.Read<uint>(_dllBytes.Span[relocation.Offset..]) + delta;
                MemoryMarshal.Write(_dllBytes.Span[relocation.Offset..], ref relocationValue);
            });
        }
        else
        {
            // Calculate the delta from the preferred base address

            var delta = (ulong) DllBaseAddress - _peImage.Headers.PEHeader!.ImageBase;

            Parallel.ForEach(_peImage.RelocationDirectory.GetRelocations(), relocation =>
            {
                if (relocation.Type != RelocationType.Dir64)
                {
                    return;
                }

                // Perform the relocation

                var relocationValue = MemoryMarshal.Read<ulong>(_dllBytes.Span[relocation.Offset..]) + delta;
                MemoryMarshal.Write(_dllBytes.Span[relocation.Offset..], ref relocationValue);
            });
        }
    }

    private void RemoveExceptionHandlers()
    {
        nint functionTableAddress;

        if (_processContext.Architecture == Architecture.X86)
        {
            try
            {
                functionTableAddress = _processContext.GetNtdllSymbolAddress("LdrpInvertedFunctionTables");
            }

            catch
            {
                functionTableAddress = _processContext.GetNtdllSymbolAddress("LdrpInvertedFunctionTable");
            }
        }
        else
        {
            functionTableAddress = _processContext.GetFunctionAddress("ntdll.dll", "KiUserInvertedFunctionTable");
        }

        using var pebLock = new PebLock(_processContext);

        // Read the function table

        var functionTable = _processContext.Process.ReadStruct<InvertedFunctionTable>(functionTableAddress);

        if (_processContext.Architecture == Architecture.X86)
        {
            var loadConfigData = _peImage.LoadConfigDirectory.GetLoadConfigData();

            if (loadConfigData is null)
            {
                return;
            }

            // Read the function table entry list

            var functionTableEntryListAddress = functionTableAddress + Unsafe.SizeOf<InvertedFunctionTable>();
            var functionTableEntryList = _processContext.Process.ReadSpan<InvertedFunctionTableEntry32>(functionTableEntryListAddress, Constants.InvertedFunctionTableSize);

            // Search for the entry index

            var removalIndex = 1;

            while (removalIndex < functionTable.CurrentSize)
            {
                if ((int) DllBaseAddress == functionTableEntryList[removalIndex].ImageBase)
                {
                    break;
                }

                removalIndex += 1;
            }

            if (removalIndex < functionTable.CurrentSize - 1)
            {
                // Shift the existing elements to overwrite the entry

                for (var entryIndex = removalIndex; entryIndex < functionTable.CurrentSize; entryIndex += 1)
                {
                    functionTableEntryList[entryIndex] = functionTableEntryList[entryIndex + 1];
                }
            }
            else
            {
                functionTableEntryList[removalIndex] = default;
            }

            // Update the function table entry list

            _processContext.Process.WriteSpan(functionTableEntryListAddress, functionTableEntryList);
        }
        else
        {
            // Read the function table entry list

            var functionTableEntryListAddress = functionTableAddress + Unsafe.SizeOf<InvertedFunctionTable>();
            var functionTableEntryList = _processContext.Process.ReadSpan<InvertedFunctionTableEntry64>(functionTableEntryListAddress, Constants.InvertedFunctionTableSize);

            // Search for the entry index

            var removalIndex = 1;

            while (removalIndex < functionTable.CurrentSize)
            {
                if (DllBaseAddress == functionTableEntryList[removalIndex].ImageBase)
                {
                    break;
                }

                removalIndex += 1;
            }

            if (removalIndex < functionTable.CurrentSize - 1)
            {
                // Shift the existing elements to overwrite the entry

                for (var entryIndex = removalIndex; entryIndex < functionTable.CurrentSize; entryIndex += 1)
                {
                    functionTableEntryList[entryIndex] = functionTableEntryList[entryIndex + 1];
                }
            }
            else
            {
                functionTableEntryList[removalIndex] = default;
            }

            // Update the function table entry list

            _processContext.Process.WriteSpan(functionTableEntryListAddress, functionTableEntryList);
        }

        // Update the function table

        functionTable = functionTable with { CurrentSize = functionTable.CurrentSize - 1, Overflow = false };
        _processContext.Process.WriteStruct(functionTableAddress, functionTable);
    }

    private void RemoveTlsData()
    {
        if (_peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.Size == 0)
        {
            return;
        }

        var status = _processContext.CallRoutine<NtStatus>(_processContext.GetNtdllSymbolAddress("LdrpReleaseTlsEntry"), CallingConvention.FastCall, _ldrEntryAddress, 0);

        if (!status.IsSuccess())
        {
            throw new Win32Exception(Ntdll.RtlNtStatusToDosError(status));
        }
    }
}