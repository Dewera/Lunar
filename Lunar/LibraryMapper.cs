using System.Diagnostics;
using System.Numerics;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Lunar.Extensions;
using Lunar.FileResolution;
using Lunar.Native;
using Lunar.Native.Enums;
using Lunar.Native.Structs;
using Lunar.PortableExecutable;
using Lunar.Remote;
using Lunar.Utilities;

namespace Lunar;

/// <summary>
/// Provides the functionality to map a DLL from disk or memory into a process
/// </summary>
public sealed class LibraryMapper
{
    /// <summary>
    /// The base address of the DLL in the process
    /// </summary>
    public IntPtr DllBaseAddress { get; private set; }

    private readonly Memory<byte> _dllBytes;
    private readonly FileResolver _fileResolver;
    private readonly MappingFlags _mappingFlags;
    private readonly PeImage _peImage;
    private readonly ProcessContext _processContext;
    private (IntPtr EntryAddress, int Index, bool ModifiedBitmap) _tlsData;

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

        _dllBytes = File.ReadAllBytes(dllFilePath);
        _fileResolver = new FileResolver(process, Path.GetDirectoryName(dllFilePath));
        _mappingFlags = mappingFlags;
        _peImage = new PeImage(File.ReadAllBytes(dllFilePath));
        _processContext = new ProcessContext(process);
    }

    /// <summary>
    /// Maps the DLL into the process
    /// </summary>
    public void MapLibrary()
    {
        if (DllBaseAddress != IntPtr.Zero)
        {
            return;
        }

        var cleanupStack = new Stack<Action>();

        try
        {
            DllBaseAddress = _processContext.Process.AllocateBuffer(_peImage.Headers.PEHeader!.SizeOfImage, ProtectionType.ReadOnly);
            cleanupStack.Push(() => _processContext.Process.FreeBuffer(DllBaseAddress));

            LoadDependencies();
            cleanupStack.Push(FreeDependencies);

            BuildImportAddressTable();
            RelocateImage();

            if (!_mappingFlags.HasFlag(MappingFlags.DiscardHeaders))
            {
                MapHeaders();
            }

            MapSections();
            InitialiseControlFlowGuard();
            InitialiseSecurityCookie();

            InsertExceptionHandlers();
            cleanupStack.Push(RemoveExceptionHandlers);

            ReserveTlsIndex();
            cleanupStack.Push(ReleaseTlsIndex);

            InitialiseTlsData();
            cleanupStack.Push(FreeTlsEntry);

            if (!_mappingFlags.HasFlag(MappingFlags.SkipInitialisationRoutines))
            {
                CallInitialisationRoutines(DllReason.ProcessAttach);
            }
        }

        catch
        {
            while (cleanupStack.TryPop(out var cleanupRoutine))
            {
                Executor.IgnoreExceptions(cleanupRoutine);
            }

            Executor.IgnoreExceptions(() => _processContext.HeapManager.FreeCachedBuffers());

            DllBaseAddress = IntPtr.Zero;
            throw;
        }
    }

    /// <summary>
    /// Unmaps the DLL from the process
    /// </summary>
    public void UnmapLibrary()
    {
        if (DllBaseAddress == IntPtr.Zero)
        {
            return;
        }

        var topLevelException = default(Exception);

        try
        {
            if (!_mappingFlags.HasFlag(MappingFlags.SkipInitialisationRoutines))
            {
                CallInitialisationRoutines(DllReason.ProcessDetach);
            }
        }

        catch (Exception exception)
        {
            topLevelException ??= exception;
        }

        try
        {
            FreeTlsEntry();
        }

        catch (Exception exception)
        {
            topLevelException ??= exception;
        }

        try
        {
            ReleaseTlsIndex();
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
            _processContext.Process.FreeBuffer(DllBaseAddress);
        }

        catch (Exception exception)
        {
            topLevelException ??= exception;
        }

        finally
        {
            DllBaseAddress = IntPtr.Zero;
        }

        try
        {
            _processContext.HeapManager.FreeCachedBuffers();
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
        // Call the entry point of any TLS callbacks

        foreach (var callbackAddress in _peImage.TlsDirectory.GetTlsCallbacks().Select(callBack => DllBaseAddress + callBack.RelativeAddress))
        {
            _processContext.CallRoutine(callbackAddress, DllBaseAddress, reason, 0);
        }

        if ((_peImage.Headers.CorHeader?.Flags.HasFlag(CorFlags.ILOnly) ?? false) || _peImage.Headers.PEHeader!.AddressOfEntryPoint == 0)
        {
            return;
        }

        // Call the DLL entry point

        var entryPointAddress = DllBaseAddress + _peImage.Headers.PEHeader!.AddressOfEntryPoint;

        if (!_processContext.CallRoutine<bool>(entryPointAddress, DllBaseAddress, reason, 0))
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

            if (!_processContext.CallRoutine<bool>(_processContext.GetFunctionAddress("kernel32.dll", "FreeLibrary"), dependencyAddress))
            {
                throw new ApplicationException($"Failed to free the dependency {dependencyName} from the process");
            }
        }

        _processContext.ClearModuleCache();
    }

    private void FreeTlsEntry()
    {
        if (_peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.Size == 0)
        {
            return;
        }

        using var pebLock = new PebLock(_processContext);

        if (_processContext.Architecture == Architecture.X86)
        {
            // Read the TLS entry

            var tlsEntry = _processContext.Process.ReadStruct<LdrpTlsEntry32>(_tlsData.EntryAddress);

            // Remove the TLS entry from the TLS list

            var previousEntryAddress = UnsafeHelpers.WrapPointer(tlsEntry.EntryLinks.Blink);
            var previousEntry = _processContext.Process.ReadStruct<ListEntry32>(previousEntryAddress);
            _processContext.Process.WriteStruct(previousEntryAddress, previousEntry with { Flink = tlsEntry.EntryLinks.Flink });

            var nextEntryAddress = UnsafeHelpers.WrapPointer(tlsEntry.EntryLinks.Flink);
            var nextEntry = _processContext.Process.ReadStruct<ListEntry32>(nextEntryAddress);
            _processContext.Process.WriteStruct(nextEntryAddress, nextEntry with { Blink = tlsEntry.EntryLinks.Blink });
        }

        else
        {
            // Read the TLS entry

            var tlsEntry = _processContext.Process.ReadStruct<LdrpTlsEntry64>(_tlsData.EntryAddress);

            // Remove the TLS entry from the TLS list

            var previousEntryAddress = UnsafeHelpers.WrapPointer(tlsEntry.EntryLinks.Blink);
            var previousEntry = _processContext.Process.ReadStruct<ListEntry64>(previousEntryAddress);
            _processContext.Process.WriteStruct(previousEntryAddress, previousEntry with { Flink = tlsEntry.EntryLinks.Flink });

            var nextEntryAddress = UnsafeHelpers.WrapPointer(tlsEntry.EntryLinks.Flink);
            var nextEntry = _processContext.Process.ReadStruct<ListEntry64>(nextEntryAddress);
            _processContext.Process.WriteStruct(nextEntryAddress, nextEntry with { Blink = tlsEntry.EntryLinks.Blink });
        }

        // Free the TLS entry

        _processContext.HeapManager.FreeBuffer(_tlsData.EntryAddress);
    }

    private void InitialiseControlFlowGuard()
    {
        var loadConfigData = _peImage.LoadConfigDirectory.GetLoadConfigData();

        if (loadConfigData is null || !loadConfigData.GuardFlags.HasFlag(GuardFlags.Instrumented))
        {
            return;
        }

        // Check if the process is using control flow guard

        if (!_processContext.CallRoutine<bool>(_processContext.GetFunctionAddress("ntdll.dll", "LdrControlFlowGuardEnforced")))
        {
            return;
        }

        // Check if the process is using export suppression

        var usingExportSuppression = false;

        if (loadConfigData.GuardFlags.HasFlag(GuardFlags.ExportSuppressionInfoPresent))
        {
            usingExportSuppression = _processContext.CallRoutine<bool>(_processContext.GetNtdllSymbolAddress("LdrControlFlowGuardEnforcedWithExportSuppression"));
        }

        var checkFunctionName = "LdrpValidateUserCallTarget";
        var dispatchFunctionName = "LdrpDispatchUserCallTarget";

        if (usingExportSuppression)
        {
            checkFunctionName = $"{checkFunctionName}ES";
            dispatchFunctionName = $"{dispatchFunctionName}ES";
        }

        // Read the load config directory

        var loadConfigDirectoryAddress = DllBaseAddress + _peImage.Headers.PEHeader!.LoadConfigTableDirectory.RelativeVirtualAddress;

        if (_peImage.Headers.PEHeader!.Magic == PEMagic.PE32)
        {
            var loadConfigDirectory = _processContext.Process.ReadStruct<ImageLoadConfigDirectory32>(loadConfigDirectoryAddress);

            // Update the check function pointer

            _processContext.Process.WriteStruct(loadConfigDirectoryAddress, loadConfigDirectory with { GuardCFCheckFunctionPointer = (int) _processContext.GetNtdllSymbolAddress(checkFunctionName) });
        }

        else
        {
            var loadConfigDirectory = _processContext.Process.ReadStruct<ImageLoadConfigDirectory64>(loadConfigDirectoryAddress);

            // Update the check and dispatch function pointers

            _processContext.Process.WriteStruct(loadConfigDirectoryAddress, loadConfigDirectory with { GuardCFCheckFunctionPointer = (long) _processContext.GetNtdllSymbolAddress(checkFunctionName), GuardCFDispatchFunctionPointer = (long) _processContext.GetNtdllSymbolAddress(dispatchFunctionName) });
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

        var securityCookieBytes = _peImage.Headers.PEHeader!.Magic == PEMagic.PE32 ? stackalloc byte[4] : stackalloc byte[6];
        RandomNumberGenerator.Fill(securityCookieBytes);

        // Ensure the default security cookie was not generated

        if (securityCookieBytes is [0xBB, 0x40, 0xE6, 0x4E] || securityCookieBytes is [0x2B, 0x99, 0x2D, 0xDF, 0xA2, 0x32])
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

        var tlsDirectoryAddress = DllBaseAddress + _peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.RelativeVirtualAddress;
        var tlsListAddress = _processContext.GetNtdllSymbolAddress("LdrpTlsList");
        using var pebLock = new PebLock(_processContext);

        if (_processContext.Architecture == Architecture.X86)
        {
            // Read the TLS directory

            var tlsDirectory = _processContext.Process.ReadStruct<ImageTlsDirectory32>(tlsDirectoryAddress);

            // Write the TLS index into the process

            var tlsIndexAddress = UnsafeHelpers.WrapPointer(tlsDirectory.AddressOfIndex);
            _processContext.Process.WriteStruct(tlsIndexAddress, _tlsData.Index);

            // Read the TLS list

            var tlsListHead = _processContext.Process.ReadStruct<ListEntry32>(tlsListAddress);
            var tlsListTailAddress = UnsafeHelpers.WrapPointer(tlsListHead.Blink);
            var tlsListTail = _processContext.Process.ReadStruct<ListEntry32>(tlsListTailAddress);

            // Write a TLS entry for the DLL into the process

            _tlsData.EntryAddress = _processContext.HeapManager.AllocateBuffer(Unsafe.SizeOf<LdrpTlsEntry32>());
            var tlsEntry = new LdrpTlsEntry32(tlsListHead with { Flink = (int) tlsListAddress }, tlsDirectory, _tlsData.Index);
            _processContext.Process.WriteStruct(_tlsData.EntryAddress, tlsEntry);

            // Insert the TLS entry into the TLS list

            if (tlsListAddress == tlsListTailAddress)
            {
                _processContext.Process.WriteStruct(tlsListAddress, new ListEntry32((int) _tlsData.EntryAddress, (int) _tlsData.EntryAddress));
            }

            else
            {
                _processContext.Process.WriteStruct(tlsListAddress, tlsListHead with { Blink = (int) _tlsData.EntryAddress });

                try
                {
                    _processContext.Process.WriteStruct(tlsListTailAddress, tlsListTail with { Flink = (int) _tlsData.EntryAddress });
                }

                catch
                {
                    Executor.IgnoreExceptions(() => _processContext.Process.WriteStruct(_tlsData.EntryAddress, tlsListHead));
                    throw;
                }
            }
        }

        else
        {
            // Read the TLS directory

            var tlsDirectory = _processContext.Process.ReadStruct<ImageTlsDirectory64>(tlsDirectoryAddress);

            // Write the TLS index into the process

            var tlsIndexAddress = UnsafeHelpers.WrapPointer(tlsDirectory.AddressOfIndex);
            _processContext.Process.WriteStruct(tlsIndexAddress, _tlsData.Index);

            // Read the TLS list

            var tlsListHead = _processContext.Process.ReadStruct<ListEntry64>(tlsListAddress);
            var tlsListTailAddress = UnsafeHelpers.WrapPointer(tlsListHead.Blink);
            var tlsListTail = _processContext.Process.ReadStruct<ListEntry64>(tlsListTailAddress);

            // Write a TLS entry for the DLL into the process heap

            _tlsData.EntryAddress = _processContext.HeapManager.AllocateBuffer(Unsafe.SizeOf<LdrpTlsEntry64>());
            var tlsEntry = new LdrpTlsEntry64(tlsListHead with { Flink = (long) tlsListAddress }, tlsDirectory, _tlsData.Index);
            _processContext.Process.WriteStruct(_tlsData.EntryAddress, tlsEntry);

            // Insert the TLS entry into the TLS list

            if (tlsListAddress == tlsListTailAddress)
            {
                _processContext.Process.WriteStruct(tlsListAddress, new ListEntry64((long) _tlsData.EntryAddress, (long) _tlsData.EntryAddress));
            }

            else
            {
                _processContext.Process.WriteStruct(tlsListAddress, tlsListHead with { Blink = (long) _tlsData.EntryAddress });

                try
                {
                    _processContext.Process.WriteStruct(tlsListTailAddress, tlsListTail with { Flink = (long) _tlsData.EntryAddress });
                }

                catch
                {
                    Executor.IgnoreExceptions(() => _processContext.Process.WriteStruct(_tlsData.EntryAddress, tlsListHead));
                    throw;
                }
            }
        }
    }

    private void InsertExceptionHandlers()
    {
        IntPtr functionTableAddress;

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
            if (_peImage.Headers.PEHeader!.Magic == PEMagic.PE32)
            {
                var loadConfigData = _peImage.LoadConfigDirectory.GetLoadConfigData();

                if (loadConfigData is null)
                {
                    return;
                }

                // Read the function table entry list

                var functionTableEntryListAddress = functionTableAddress + Unsafe.SizeOf<InvertedFunctionTable>();
                var functionTableEntryList = _processContext.Process.ReadSpan<InvertedFunctionTableEntry32>(functionTableEntryListAddress, Constants.InvertedFunctionTableSize);

                // Find the index where the entry for the DLL should be inserted

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
                    // Shift the existing elements to make space for the entry for the DLL

                    for (var entryIndex = functionTable.CurrentSize - 1; entryIndex >= insertionIndex; entryIndex -= 1)
                    {
                        functionTableEntryList[entryIndex + 1] = functionTableEntryList[entryIndex];
                    }
                }

                // Read the shared user data

                var sharedUserDataAddress = UnsafeHelpers.WrapPointer(Constants.SharedUserDataAddress);
                var sharedUserData = _processContext.Process.ReadStruct<KUserSharedData>(sharedUserDataAddress);

                // Encode the address of the exception directory using the system pointer encoding algorithm

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

                // Find the index where the entry for the DLL should be inserted

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
                    // Shift the existing elements to make space for the entry for the DLL

                    for (var entryIndex = functionTable.CurrentSize - 1; entryIndex >= insertionIndex; entryIndex -= 1)
                    {
                        functionTableEntryList[entryIndex + 1] = functionTableEntryList[entryIndex];
                    }
                }

                // Update the function table entry list

                var exceptionDirectoryAddress = DllBaseAddress + _peImage.Headers.PEHeader!.ExceptionTableDirectory.RelativeVirtualAddress;
                functionTableEntryList[insertionIndex] = new InvertedFunctionTableEntry64((long) exceptionDirectoryAddress, (long) DllBaseAddress, _peImage.Headers.PEHeader!.SizeOfImage, _peImage.Headers.PEHeader!.ExceptionTableDirectory.Size);
                _processContext.Process.WriteSpan(functionTableEntryListAddress, functionTableEntryList);
            }

            // Update the function table size

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

                var dependencyAddress = _processContext.CallRoutine<IntPtr>(_processContext.GetFunctionAddress("kernel32.dll", "LoadLibraryW"), dependencyFilePathAddress);

                if (dependencyAddress == IntPtr.Zero)
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

    private void ReleaseTlsIndex()
    {
        if (_peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.Size == 0)
        {
            return;
        }

        var tlsBitmapAddress = _processContext.GetNtdllSymbolAddress("LdrpTlsBitmap");

        // Clear the index from the TLS bitmap

        _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlClearBit"), tlsBitmapAddress, _tlsData.Index);
    }

    private void RelocateImage()
    {
        if (_peImage.Headers.PEHeader!.Magic == PEMagic.PE32)
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

    private void ReserveTlsIndex()
    {
        if (_peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.Size == 0)
        {
            return;
        }

        var actualTlsBitmapSizeAddress = _processContext.GetNtdllSymbolAddress("LdrpActualBitmapSize");
        var initialTlsBitmapBufferAddress = _processContext.GetNtdllSymbolAddress("LdrpStaticTlsBitmapVector");
        var tlsBitmapAddress = _processContext.GetNtdllSymbolAddress("LdrpTlsBitmap");
        using var pebLock = new PebLock(_processContext);

        if (_processContext.Architecture == Architecture.X86)
        {
            // Read the TLS bitmap

            var tlsBitmap = _processContext.Process.ReadStruct<RtlBitmap32>(tlsBitmapAddress);

            if (tlsBitmap.SizeOfBitmap == 0)
            {
                tlsBitmap = new RtlBitmap32(Buffer: (int) initialTlsBitmapBufferAddress, SizeOfBitmap: Constants.TlsBitmapSize);

                // Initialise the actual TLS bitmap size

                _processContext.Process.WriteStruct(actualTlsBitmapSizeAddress, 1);
            }

            else
            {
                // Try reserve an index in the TLS bitmap

                _tlsData.Index = _processContext.CallRoutine<int>(_processContext.GetFunctionAddress("ntdll.dll", "RtlFindClearBitsAndSet"), tlsBitmapAddress, 1, 0);

                if (_tlsData.Index != -1)
                {
                    _tlsData.ModifiedBitmap = false;

                    return;
                }

                // Check if the TLS bitmap buffer needs to be extended

                var actualBitmapSize = _processContext.Process.ReadStruct<int>(actualTlsBitmapSizeAddress);
                var actualBitmapSizeIncrement = (tlsBitmap.SizeOfBitmap + Constants.TlsBitmapIncrement32) >> 5;

                if (actualBitmapSize < actualBitmapSizeIncrement)
                {
                    // Allocate an extended TLS bitmap buffer in the process heap

                    var newTlsBitmapBufferAddress = _processContext.HeapManager.AllocateBuffer(actualBitmapSizeIncrement);

                    // Copy over the current TLS bitmap buffer data

                    var currentTlsBitmapBufferAddress = UnsafeHelpers.WrapPointer(tlsBitmap.Buffer);
                    var currentTlsBitmapBufferSize = (tlsBitmap.SizeOfBitmap + 7) >> 3;
                    var currentTlsBitmapBuffer = _processContext.Process.ReadSpan<byte>(currentTlsBitmapBufferAddress, currentTlsBitmapBufferSize);
                    _processContext.Process.WriteSpan(newTlsBitmapBufferAddress, currentTlsBitmapBuffer);

                    if (currentTlsBitmapBufferAddress != initialTlsBitmapBufferAddress)
                    {
                        // Free the current TLS bitmap buffer

                        _processContext.HeapManager.FreeBuffer(currentTlsBitmapBufferAddress);
                    }

                    tlsBitmap = new RtlBitmap32(Buffer: (int) newTlsBitmapBufferAddress, SizeOfBitmap: tlsBitmap.SizeOfBitmap + Constants.TlsBitmapSize);

                    // Update the actual TLS bitmap size

                    _processContext.Process.WriteStruct(actualTlsBitmapSizeAddress, actualBitmapSizeIncrement);
                }

                else
                {
                    tlsBitmap = tlsBitmap with { SizeOfBitmap = tlsBitmap.SizeOfBitmap + Constants.TlsBitmapSize };
                }
            }

            // Update the TLS bitmap

            _processContext.Process.WriteStruct(tlsBitmapAddress, tlsBitmap);
        }

        else
        {
            // Read the TLS bitmap

            var tlsBitmap = _processContext.Process.ReadStruct<RtlBitmap64>(tlsBitmapAddress);

            if (tlsBitmap.SizeOfBitmap == 0)
            {
                tlsBitmap = new RtlBitmap64(Buffer: (long) initialTlsBitmapBufferAddress, SizeOfBitmap: Constants.TlsBitmapSize);

                // Initialise the actual TLS bitmap size

                _processContext.Process.WriteStruct(actualTlsBitmapSizeAddress, 1);
            }

            else
            {
                // Try reserve an index in the TLS bitmap

                _tlsData.Index = _processContext.CallRoutine<int>(_processContext.GetFunctionAddress("ntdll.dll", "RtlFindClearBitsAndSet"), tlsBitmapAddress, 1, 0);

                if (_tlsData.Index != -1)
                {
                    _tlsData.ModifiedBitmap = false;

                    return;
                }

                // Check if the TLS bitmap buffer needs to be extended

                var actualBitmapSize = _processContext.Process.ReadStruct<int>(actualTlsBitmapSizeAddress);
                var actualBitmapSizeIncrement = (tlsBitmap.SizeOfBitmap + Constants.TlsBitmapIncrement64) >> 5;

                if (actualBitmapSize < actualBitmapSizeIncrement)
                {
                    // Allocate a new TLS bitmap buffer in the process heap

                    var newTlsBitmapBufferAddress = _processContext.HeapManager.AllocateBuffer(actualBitmapSizeIncrement);

                    // Copy over the current TLS bitmap buffer data

                    var currentTlsBitmapBufferAddress = UnsafeHelpers.WrapPointer(tlsBitmap.Buffer);
                    var currentTlsBitmapBufferSize = (tlsBitmap.SizeOfBitmap + 7) >> 3;
                    var currentTlsBitmapBuffer = _processContext.Process.ReadSpan<byte>(currentTlsBitmapBufferAddress, currentTlsBitmapBufferSize);
                    _processContext.Process.WriteSpan(newTlsBitmapBufferAddress, currentTlsBitmapBuffer);

                    if (currentTlsBitmapBufferAddress != initialTlsBitmapBufferAddress)
                    {
                        // Free the current TLS bitmap buffer

                        _processContext.HeapManager.FreeBuffer(currentTlsBitmapBufferAddress);
                    }

                    tlsBitmap = new RtlBitmap64(Buffer: (long) newTlsBitmapBufferAddress, SizeOfBitmap: tlsBitmap.SizeOfBitmap + Constants.TlsBitmapSize);

                    // Update the actual TLS bitmap size

                    _processContext.Process.WriteStruct(actualTlsBitmapSizeAddress, actualBitmapSizeIncrement);
                }

                else
                {
                    tlsBitmap = tlsBitmap with { SizeOfBitmap = tlsBitmap.SizeOfBitmap + Constants.TlsBitmapSize };
                }
            }

            // Update the TLS bitmap

            _processContext.Process.WriteStruct(tlsBitmapAddress, tlsBitmap);
        }

        _tlsData.ModifiedBitmap = true;

        // Reserve an index in the TLS bitmap

        _tlsData.Index = _processContext.CallRoutine<int>(_processContext.GetFunctionAddress("ntdll.dll", "RtlFindClearBitsAndSet"), tlsBitmapAddress, 1, 0);

        if (_tlsData.Index == -1)
        {
            throw new ApplicationException("Failed to reserve a TLS index in the TLS bitmap");
        }
    }

    private void RemoveExceptionHandlers()
    {
        IntPtr functionTableAddress;

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

        if (_peImage.Headers.PEHeader!.Magic == PEMagic.PE32)
        {
            var loadConfigData = _peImage.LoadConfigDirectory.GetLoadConfigData();

            if (loadConfigData is null)
            {
                return;
            }

            // Read the function table entry list

            var functionTableEntryListAddress = functionTableAddress + Unsafe.SizeOf<InvertedFunctionTable>();
            var functionTableEntryList = _processContext.Process.ReadSpan<InvertedFunctionTableEntry32>(functionTableEntryListAddress, Constants.InvertedFunctionTableSize);

            // Find the index where the entry for the DLL should be removed

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
                // Shift the existing elements to overwrite the entry for the DLL

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

            // Find the index where the entry for the DLL should be removed

            var removalIndex = 1;

            while (removalIndex < functionTable.CurrentSize)
            {
                if ((long) DllBaseAddress == functionTableEntryList[removalIndex].ImageBase)
                {
                    break;
                }

                removalIndex += 1;
            }

            if (removalIndex < functionTable.CurrentSize - 1)
            {
                // Shift the existing elements to overwrite the entry for the DLL

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

        // Update the function table size

        functionTable = functionTable with { CurrentSize = functionTable.CurrentSize - 1, Overflow = false };
        _processContext.Process.WriteStruct(functionTableAddress, functionTable);
    }
}