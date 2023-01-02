﻿using System.Diagnostics;
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
    private readonly MappingFlags _mappingFlags;
    private readonly PeImage _peImage;
    private readonly ProcessContext _processContext;
    private (nint EntryAddress, int Index) _tlsData;

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
            DllBaseAddress = _processContext.Process.AllocateBuffer(_peImage.Headers.PEHeader!.SizeOfImage, ProtectionType.ReadOnly);
            cleanupStack.Push(() => _processContext.Process.FreeBuffer(DllBaseAddress));

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

            ReserveTlsIndex();
            cleanupStack.Push(ReleaseTlsIndex);

            InitialiseTlsData();
            cleanupStack.Push(FreeTlsEntry);

            CallInitialisationRoutines(DllReason.ProcessAttach);
        }

        catch
        {
            while (cleanupStack.TryPop(out var cleanupRoutine))
            {
                Executor.IgnoreExceptions(cleanupRoutine);
            }

            Executor.IgnoreExceptions(() => _processContext.HeapManager.FreeCachedBuffers());

            DllBaseAddress = 0;
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
            DllBaseAddress = 0;
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
        if (_mappingFlags.HasFlag(MappingFlags.SkipInitRoutines))
        {
            return;
        }

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

            var previousEntry = _processContext.Process.ReadStruct<ListEntry32>(tlsEntry.EntryLinks.Blink);
            _processContext.Process.WriteStruct(tlsEntry.EntryLinks.Blink, previousEntry with { Flink = tlsEntry.EntryLinks.Flink });

            var nextEntry = _processContext.Process.ReadStruct<ListEntry32>(tlsEntry.EntryLinks.Flink);
            _processContext.Process.WriteStruct(tlsEntry.EntryLinks.Flink, nextEntry with { Blink = tlsEntry.EntryLinks.Blink });
        }

        else
        {
            // Read the TLS entry

            var tlsEntry = _processContext.Process.ReadStruct<LdrpTlsEntry64>(_tlsData.EntryAddress);

            // Remove the TLS entry from the TLS list

            var previousEntry = _processContext.Process.ReadStruct<ListEntry64>((nint) tlsEntry.EntryLinks.Blink);
            _processContext.Process.WriteStruct((nint) tlsEntry.EntryLinks.Blink, previousEntry with { Flink = tlsEntry.EntryLinks.Flink });

            var nextEntry = _processContext.Process.ReadStruct<ListEntry64>((nint) tlsEntry.EntryLinks.Flink);
            _processContext.Process.WriteStruct((nint) tlsEntry.EntryLinks.Flink, nextEntry with { Blink = tlsEntry.EntryLinks.Blink });
        }

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

        var tlsDirectoryAddress = DllBaseAddress + _peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.RelativeVirtualAddress;
        var tlsListAddress = _processContext.GetNtdllSymbolAddress("LdrpTlsList");

        using var pebLock = new PebLock(_processContext);

        if (_processContext.Architecture == Architecture.X86)
        {
            // Write the TLS index into the process

            var tlsDirectory = _processContext.Process.ReadStruct<ImageTlsDirectory32>(tlsDirectoryAddress);
            _processContext.Process.WriteStruct(tlsDirectory.AddressOfIndex, _tlsData.Index);

            // Read the TLS list

            var tlsListHead = _processContext.Process.ReadStruct<ListEntry32>(tlsListAddress);
            var tlsListTail = _processContext.Process.ReadStruct<ListEntry32>(tlsListHead.Blink);

            // Write a TLS entry into the process

            var tlsEntry = new LdrpTlsEntry32(tlsListHead with { Flink = (int) tlsListAddress }, tlsDirectory, _tlsData.Index);
            _tlsData.EntryAddress = _processContext.HeapManager.AllocateBuffer(Unsafe.SizeOf<LdrpTlsEntry32>());
            _processContext.Process.WriteStruct(_tlsData.EntryAddress, tlsEntry);

            // Insert the TLS entry into the TLS list

            if (tlsListAddress == tlsListHead.Blink)
            {
                _processContext.Process.WriteStruct(tlsListAddress, new ListEntry32((int) _tlsData.EntryAddress, (int) _tlsData.EntryAddress));
            }

            else
            {
                _processContext.Process.WriteStruct(tlsListAddress, tlsListHead with { Blink = (int) _tlsData.EntryAddress });
                _processContext.Process.WriteStruct(tlsListHead.Blink, tlsListTail with { Flink = (int) _tlsData.EntryAddress });
            }
        }

        else
        {
            // Write the TLS index into the process

            var tlsDirectory = _processContext.Process.ReadStruct<ImageTlsDirectory64>(tlsDirectoryAddress);
            _processContext.Process.WriteStruct((nint) tlsDirectory.AddressOfIndex, _tlsData.Index);

            // Read the TLS list

            var tlsListHead = _processContext.Process.ReadStruct<ListEntry64>(tlsListAddress);
            var tlsListTail = _processContext.Process.ReadStruct<ListEntry64>((nint) tlsListHead.Blink);

            // Write a TLS entry into the process

            var tlsEntry = new LdrpTlsEntry64(tlsListHead with { Flink = tlsListAddress }, tlsDirectory, _tlsData.Index);
            _tlsData.EntryAddress = _processContext.HeapManager.AllocateBuffer(Unsafe.SizeOf<LdrpTlsEntry64>());
            _processContext.Process.WriteStruct(_tlsData.EntryAddress, tlsEntry);

            // Insert the TLS entry into the TLS list

            if (tlsListAddress == tlsListHead.Blink)
            {
                _processContext.Process.WriteStruct(tlsListAddress, new ListEntry64(_tlsData.EntryAddress, _tlsData.EntryAddress));
            }

            else
            {
                _processContext.Process.WriteStruct(tlsListAddress, tlsListHead with { Blink = _tlsData.EntryAddress });
                _processContext.Process.WriteStruct((nint) tlsListHead.Blink, tlsListTail with { Flink = _tlsData.EntryAddress });
            }
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

                var dependencyAddress = _processContext.CallRoutine<nint>(_processContext.GetFunctionAddress("kernel32.dll", "LoadLibraryW"), dependencyFilePathAddress);

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

    private void ReleaseTlsIndex()
    {
        if (_peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.Size == 0)
        {
            return;
        }

        var tlsBitmapAddress = _processContext.GetNtdllSymbolAddress("LdrpTlsBitmap");
        var tlsBitmapBufferSizeAddress = _processContext.GetNtdllSymbolAddress("LdrpActualBitmapSize");

        using var pebLock = new PebLock(_processContext);

        // Read the TLS bitmap buffer

        nint bitmapBufferAddress;

        if (_processContext.Architecture == Architecture.X86)
        {
            var tlsBitmap = _processContext.Process.ReadStruct<RtlBitmap32>(tlsBitmapAddress);
            bitmapBufferAddress = tlsBitmap.Buffer;
        }

        else
        {
            var tlsBitmap = _processContext.Process.ReadStruct<RtlBitmap64>(tlsBitmapAddress);
            bitmapBufferAddress = (nint) tlsBitmap.Buffer;
        }

        var tlsBitmapBufferSize = _processContext.Process.ReadStruct<int>(tlsBitmapBufferSizeAddress);
        var tlsBitmapBuffer = _processContext.Process.ReadSpan<byte>(bitmapBufferAddress, tlsBitmapBufferSize);

        // Clear the TLS index

        BitmapManager.ClearBit(ref tlsBitmapBuffer, _tlsData.Index);
        _processContext.Process.WriteSpan(bitmapBufferAddress, tlsBitmapBuffer);
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

    private void ReserveTlsIndex()
    {
        if (_peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.Size == 0)
        {
            return;
        }

        var initialTlsBitmapBufferAddress = _processContext.GetNtdllSymbolAddress("LdrpStaticTlsBitmapVector");
        var tlsBitmapAddress = _processContext.GetNtdllSymbolAddress("LdrpTlsBitmap");
        var tlsBitmapBufferSizeAddress = _processContext.GetNtdllSymbolAddress("LdrpActualBitmapSize");

        using var pebLock = new PebLock(_processContext);

        if (_processContext.Architecture == Architecture.X86)
        {
            // Read the TLS bitmap

            var tlsBitmap = _processContext.Process.ReadStruct<RtlBitmap32>(tlsBitmapAddress);

            if (tlsBitmap.SizeOfBitmap == 0)
            {
                // Initialise the TLS bitmap

                tlsBitmap = new RtlBitmap32(8, (int) initialTlsBitmapBufferAddress);
                _processContext.Process.WriteStruct(tlsBitmapBufferSizeAddress, 1);
            }

            // Try reserve a TLS index

            var tlsBitmapBuffer = _processContext.Process.ReadSpan<byte>(tlsBitmap.Buffer, tlsBitmap.SizeOfBitmap / 8);
            _tlsData.Index = BitmapManager.FindClearBitAndSet(ref tlsBitmapBuffer);

            if (_tlsData.Index == -1)
            {
                // Check if the TLS bitmap buffer needs to be reallocated

                var tlsBitmapBufferSize = _processContext.Process.ReadStruct<int>(tlsBitmapBufferSizeAddress);
                var tlsBitmapBufferSizeIncrement = tlsBitmap.SizeOfBitmap + Constants.TlsBitmapIncrement32 >> 5;

                if (tlsBitmapBufferSize < tlsBitmapBufferSizeIncrement)
                {
                    // Reallocate the TLS bitmap buffer and copy over the existing data

                    var newTlsBitmapBufferAddress = _processContext.HeapManager.AllocateBuffer(tlsBitmapBufferSizeIncrement);
                    _processContext.Process.WriteSpan(newTlsBitmapBufferAddress, tlsBitmapBuffer);

                    if (tlsBitmap.Buffer != initialTlsBitmapBufferAddress)
                    {
                        _processContext.HeapManager.FreeBuffer(tlsBitmap.Buffer);
                    }

                    // Reinitialise the TLS bitmap

                    tlsBitmap = new RtlBitmap32(tlsBitmap.SizeOfBitmap + 8, (int) newTlsBitmapBufferAddress);
                    _processContext.Process.WriteStruct(tlsBitmapBufferSizeAddress, tlsBitmapBufferSizeIncrement);
                }

                else
                {
                    tlsBitmap = tlsBitmap with { SizeOfBitmap = tlsBitmap.SizeOfBitmap + 8 };
                }

                // Reserve a TLS index

                tlsBitmapBuffer = _processContext.Process.ReadSpan<byte>(tlsBitmap.Buffer, tlsBitmap.SizeOfBitmap / 8);
                _tlsData.Index = BitmapManager.FindClearBitAndSet(ref tlsBitmapBuffer);
            }

            // Update the TLS bitmap

            _processContext.Process.WriteSpan(tlsBitmap.Buffer, tlsBitmapBuffer);
            _processContext.Process.WriteStruct(tlsBitmapAddress, tlsBitmap);
        }

        else
        {
            // Read the TLS bitmap

            var tlsBitmap = _processContext.Process.ReadStruct<RtlBitmap64>(tlsBitmapAddress);

            if (tlsBitmap.SizeOfBitmap == 0)
            {
                // Initialise the TLS bitmap

                tlsBitmap = new RtlBitmap64(8, initialTlsBitmapBufferAddress);
                _processContext.Process.WriteStruct(tlsBitmapBufferSizeAddress, 1);
            }

            // Try reserve a TLS index

            var tlsBitmapBuffer = _processContext.Process.ReadSpan<byte>((nint) tlsBitmap.Buffer, tlsBitmap.SizeOfBitmap / 8);
            _tlsData.Index = BitmapManager.FindClearBitAndSet(ref tlsBitmapBuffer);

            if (_tlsData.Index == -1)
            {
                // Check if the TLS bitmap buffer needs to be reallocated

                var tlsBitmapBufferSize = _processContext.Process.ReadStruct<int>(tlsBitmapBufferSizeAddress);
                var tlsBitmapBufferSizeIncrement = tlsBitmap.SizeOfBitmap + Constants.TlsBitmapIncrement64 >> 5;

                if (tlsBitmapBufferSize < tlsBitmapBufferSizeIncrement)
                {
                    // Reallocate the TLS bitmap buffer and copy over the existing data

                    var newTlsBitmapBufferAddress = _processContext.HeapManager.AllocateBuffer(tlsBitmapBufferSizeIncrement);
                    _processContext.Process.WriteSpan(newTlsBitmapBufferAddress, tlsBitmapBuffer);

                    if (tlsBitmap.Buffer != initialTlsBitmapBufferAddress)
                    {
                        _processContext.HeapManager.FreeBuffer((nint) tlsBitmap.Buffer);
                    }

                    // Reinitialise the TLS bitmap

                    tlsBitmap = new RtlBitmap64(tlsBitmap.SizeOfBitmap + 8, newTlsBitmapBufferAddress);
                    _processContext.Process.WriteStruct(tlsBitmapBufferSizeAddress, tlsBitmapBufferSizeIncrement);
                }

                else
                {
                    tlsBitmap = tlsBitmap with { SizeOfBitmap = tlsBitmap.SizeOfBitmap + 8 };
                }

                // Reserve a TLS index

                tlsBitmapBuffer = _processContext.Process.ReadSpan<byte>((nint) tlsBitmap.Buffer, tlsBitmap.SizeOfBitmap / 8);
                _tlsData.Index = BitmapManager.FindClearBitAndSet(ref tlsBitmapBuffer);
            }

            // Update the TLS bitmap

            _processContext.Process.WriteSpan((nint) tlsBitmap.Buffer, tlsBitmapBuffer);
            _processContext.Process.WriteStruct(tlsBitmapAddress, tlsBitmap);
        }
    }
}