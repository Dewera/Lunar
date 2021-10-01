using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Lunar.Extensions;
using Lunar.FileResolution;
using Lunar.Native;
using Lunar.Native.Enums;
using Lunar.Native.Structs;
using Lunar.PortableExecutable;
using Lunar.Remote;
using Lunar.Utilities;

namespace Lunar
{
    /// <summary>
    /// Provides the functionality to map a DLL from disk or memory into a process
    /// </summary>
    public sealed class LibraryMapper
    {
        /// <summary>
        /// The current base address of the DLL in the process
        /// </summary>
        public IntPtr DllBaseAddress { get; private set; }

        private readonly Memory<byte> _dllBytes;
        private readonly FileResolver _fileResolver;
        private readonly MappingFlags _mappingFlags;
        private readonly PeImage _peImage;
        private readonly ProcessContext _processContext;
        private (bool AllocatedBitmap, int Index) _tlsData;

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

            // Prefetch symbols to avoid accidental deadlocks if mapping into the local process

            _processContext.PrefetchNtdllSymbols(new[] { "LdrpActualBitmapSize", "LdrpDelayedTlsReclaimTable", "LdrpInvertedFunctionTable", "LdrpInvertedFunctionTable", "LdrpTlsBitmap", "LdrpTlsBitmap" });
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

            // Prefetch symbols to avoid accidental deadlocks if mapping into the local process

            _processContext.PrefetchNtdllSymbols(new[] { "LdrpActualBitmapSize", "LdrpDelayedTlsReclaimTable", "LdrpInvertedFunctionTable", "LdrpInvertedFunctionTable", "LdrpTlsBitmap", "LdrpTlsBitmap" });
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

            DllBaseAddress = _processContext.Process.AllocateBuffer(_peImage.Headers.PEHeader!.SizeOfImage, ProtectionType.ReadOnly);

            try
            {
                LoadDependencies();

                try
                {
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

                    try
                    {
                        ReserveTlsIndex();

                        try
                        {
                            InitialiseTlsData();

                            try
                            {
                                if (_mappingFlags.HasFlag(MappingFlags.SkipInitialisationRoutines))
                                {
                                    return;
                                }

                                CallInitialisationRoutines(DllReason.ProcessAttach);
                            }

                            catch
                            {
                                Executor.IgnoreExceptions(FreeTlsEntry);
                                throw;
                            }
                        }

                        catch
                        {
                            Executor.IgnoreExceptions(ReleaseTlsIndex);
                            throw;
                        }
                    }

                    catch
                    {
                        Executor.IgnoreExceptions(RemoveExceptionHandlers);
                        throw;
                    }
                }

                catch
                {
                    Executor.IgnoreExceptions(FreeDependencies);
                    throw;
                }
            }

            catch
            {
                Executor.IgnoreExceptions(() => _processContext.Process.FreeBuffer(DllBaseAddress));
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

            if (_peImage.Headers.PEHeader!.AddressOfEntryPoint == 0)
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
            using var pebLock = new SafePebLock(_processContext);

            if (_peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.Size == 0)
            {
                return;
            }

            var tlsListAddress = _processContext.GetNtdllSymbolAddress("LdrpTlsList");

            if (_processContext.Process.GetArchitecture() == Architecture.X86)
            {
                // Find the TLS entry in the TLS list

                var tlsListHead = _processContext.Process.ReadStruct<ListEntry32>(tlsListAddress);
                var currentTlsEntryAddress = UnsafeHelpers.WrapPointer(tlsListHead.Flink);
                var currentTlsEntry = _processContext.Process.ReadStruct<LdrpTlsEntry32>(currentTlsEntryAddress);

                while (true)
                {
                    if (currentTlsEntry.Index == _tlsData.Index)
                    {
                        break;
                    }

                    // Read the next TLS entry

                    currentTlsEntryAddress = UnsafeHelpers.WrapPointer(currentTlsEntry.EntryLinks.Flink);
                    currentTlsEntry = _processContext.Process.ReadStruct<LdrpTlsEntry32>(currentTlsEntryAddress);
                }

                // Remove the TLS entry from the TLS list

                var previousListEntryAddress = UnsafeHelpers.WrapPointer(currentTlsEntry.EntryLinks.Blink);
                var previousListEntry = _processContext.Process.ReadStruct<ListEntry32>(previousListEntryAddress);
                previousListEntry = new ListEntry32(currentTlsEntry.EntryLinks.Flink, previousListEntry.Blink);
                _processContext.Process.WriteStruct(previousListEntryAddress, previousListEntry);

                var nextListEntryAddress = UnsafeHelpers.WrapPointer(currentTlsEntry.EntryLinks.Flink);
                var nextListEntry = _processContext.Process.ReadStruct<ListEntry32>(nextListEntryAddress);
                nextListEntry = new ListEntry32(nextListEntry.Flink, currentTlsEntry.EntryLinks.Blink);
                _processContext.Process.WriteStruct(nextListEntryAddress, nextListEntry);

                // Free the TLS entry

                _processContext.Process.FreeBuffer(currentTlsEntryAddress);
            }

            else
            {
                // Find the TLS entry in the TLS list

                var tlsListHead = _processContext.Process.ReadStruct<ListEntry64>(tlsListAddress);
                var currentTlsEntryAddress = UnsafeHelpers.WrapPointer(tlsListHead.Flink);
                var currentTlsEntry = _processContext.Process.ReadStruct<LdrpTlsEntry64>(currentTlsEntryAddress);

                while (true)
                {
                    if (currentTlsEntry.Index == _tlsData.Index)
                    {
                        break;
                    }

                    // Read the next TLS entry

                    currentTlsEntryAddress = UnsafeHelpers.WrapPointer(currentTlsEntry.EntryLinks.Flink);
                    currentTlsEntry = _processContext.Process.ReadStruct<LdrpTlsEntry64>(currentTlsEntryAddress);
                }

                // Remove the TLS entry from the TLS list

                var previousListEntryAddress = UnsafeHelpers.WrapPointer(currentTlsEntry.EntryLinks.Blink);
                var previousListEntry = _processContext.Process.ReadStruct<ListEntry64>(previousListEntryAddress);
                previousListEntry = new ListEntry64(currentTlsEntry.EntryLinks.Flink, previousListEntry.Blink);
                _processContext.Process.WriteStruct(previousListEntryAddress, previousListEntry);

                var nextListEntryAddress = UnsafeHelpers.WrapPointer(currentTlsEntry.EntryLinks.Flink);
                var nextListEntry = _processContext.Process.ReadStruct<ListEntry64>(nextListEntryAddress);
                nextListEntry = new ListEntry64(nextListEntry.Flink, currentTlsEntry.EntryLinks.Blink);
                _processContext.Process.WriteStruct(nextListEntryAddress, nextListEntry);

                // Free the TLS entry

                _processContext.Process.FreeBuffer(currentTlsEntryAddress);
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

            // Get the address of the control flow guard functions

            var checkFunctionName = "LdrpValidateUserCallTarget";
            var dispatchFunctionName = "LdrpDispatchUserCallTarget";

            if (usingExportSuppression)
            {
                checkFunctionName = $"{checkFunctionName}ES";
                dispatchFunctionName = $"{dispatchFunctionName}ES";
            }

            var checkFunctionAddress = _processContext.GetNtdllSymbolAddress(checkFunctionName);
            var dispatchFunctionAddress = _peImage.Headers.PEHeader!.Magic == PEMagic.PE32 ? IntPtr.Zero : _processContext.GetNtdllSymbolAddress(dispatchFunctionName);

            // Update the load config directory control flow guard function pointers

            var loadConfigDirectoryAddress = DllBaseAddress + _peImage.Headers.PEHeader!.LoadConfigTableDirectory.RelativeVirtualAddress;

            IntPtr checkFunctionUpdateAddress;

            if (_peImage.Headers.PEHeader!.Magic == PEMagic.PE32)
            {
                checkFunctionUpdateAddress = loadConfigDirectoryAddress + Marshal.OffsetOf<ImageLoadConfigDirectory32>("GuardCFCheckFunctionPointer").ToInt32();
            }

            else
            {
                checkFunctionUpdateAddress = loadConfigDirectoryAddress + Marshal.OffsetOf<ImageLoadConfigDirectory64>("GuardCFCheckFunctionPointer").ToInt32();
            }

            _processContext.Process.WriteStruct(checkFunctionUpdateAddress, checkFunctionAddress);

            if (_peImage.Headers.PEHeader!.Magic == PEMagic.PE32)
            {
                return;
            }

            var dispatchFunctionUpdateAddress = loadConfigDirectoryAddress + Marshal.OffsetOf<ImageLoadConfigDirectory64>("GuardCFDispatchFunctionPointer").ToInt32();
            _processContext.Process.WriteStruct(dispatchFunctionUpdateAddress, dispatchFunctionAddress);
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

            if (securityCookieBytes.SequenceEqual(stackalloc byte[] {0xBB, 0x40, 0xE6, 0x4E}) || securityCookieBytes.SequenceEqual(stackalloc byte[] {0x2B, 0x99, 0x2D, 0xDF, 0xA2, 0x32}))
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

            var delayedTlsReclaimTableAddress = _processContext.GetNtdllSymbolAddress("LdrpDelayedTlsReclaimTable");
            var processHeapAddress = _processContext.GetHeapAddress();
            var tlsBitmapAddress = _processContext.GetNtdllSymbolAddress("LdrpTlsBitmap");
            var tlsDirectoryAddress = DllBaseAddress + _peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.RelativeVirtualAddress;
            var tlsListAddress = _processContext.GetNtdllSymbolAddress("LdrpTlsList");

            // Preallocate heap memory to be used for the TLS data initialisation

            var tlsDataAddresses = new List<IntPtr>();
            var newTlsVectorAddresses = new List<IntPtr>();

            SafePebLock pebLock;

            while (true)
            {
                _processContext.Process.Refresh();

                if (_processContext.Process.GetArchitecture() == Architecture.X86)
                {
                    // Read the TLS directory

                    var tlsDirectory = _processContext.Process.ReadStruct<ImageTlsDirectory32>(tlsDirectoryAddress);
                    var tlsDataSize = tlsDirectory.EndAddressOfRawData - tlsDirectory.StartAddressOfRawData;

                    foreach (var _ in _processContext.Process.Threads.Cast<ProcessThread>().Skip(tlsDataAddresses.Count))
                    {
                        // Allocate a TLS data buffer for the thread

                        var tlsDataAddress = UnsafeHelpers.WrapPointer(_processContext.CallRoutine<int>(_processContext.GetFunctionAddress("kernel32.dll", "HeapAlloc"), processHeapAddress, HeapAllocationType.ZeroMemory, tlsDataSize));

                        if (tlsDataAddress == IntPtr.Zero)
                        {
                            throw new ApplicationException("Failed to allocate a TLS data buffer in the process");
                        }

                        tlsDataAddresses.Add(tlsDataAddress);

                        if (!_tlsData.AllocatedBitmap)
                        {
                            continue;
                        }

                        // Read the TLS bitmap

                        var tlsBitmap = _processContext.Process.ReadStruct<RtlBitmap32>(tlsBitmapAddress);
                        var tlsVectorSize = Unsafe.SizeOf<TlsVector32>() + sizeof(int) * tlsBitmap.SizeOfBitmap;

                        // Allocate a new TLS vector buffer for the thread

                        var newTlsVectorAddress = UnsafeHelpers.WrapPointer(_processContext.CallRoutine<int>(_processContext.GetFunctionAddress("kernel32.dll", "HeapAlloc"), processHeapAddress, HeapAllocationType.ZeroMemory, tlsVectorSize));

                        if (newTlsVectorAddress == IntPtr.Zero)
                        {
                            throw new ApplicationException("Failed to allocate a new TLS vector buffer in the process");
                        }

                        newTlsVectorAddresses.Add(newTlsVectorAddress);
                    }

                    // Ensure enough buffers were allocated

                    pebLock = new SafePebLock(_processContext);
                    _processContext.Process.Refresh();

                    if (_processContext.Process.Threads.Count <= tlsDataAddresses.Count)
                    {
                        break;
                    }

                    pebLock.Dispose();
                }

                else
                {
                    // Read the TLS directory

                    var tlsDirectory = _processContext.Process.ReadStruct<ImageTlsDirectory64>(tlsDirectoryAddress);
                    var tlsDataSize = tlsDirectory.EndAddressOfRawData - tlsDirectory.StartAddressOfRawData;

                    foreach (var _ in _processContext.Process.Threads.Cast<ProcessThread>().Skip(tlsDataAddresses.Count))
                    {
                        // Allocate a TLS data buffer for the thread

                        var tlsDataAddress = UnsafeHelpers.WrapPointer(_processContext.CallRoutine<long>(_processContext.GetFunctionAddress("kernel32.dll", "HeapAlloc"), processHeapAddress, HeapAllocationType.ZeroMemory, tlsDataSize));

                        if (tlsDataAddress == IntPtr.Zero)
                        {
                            throw new ApplicationException("Failed to allocate a TLS data buffer in the process");
                        }

                        tlsDataAddresses.Add(tlsDataAddress);

                        if (!_tlsData.AllocatedBitmap)
                        {
                            continue;
                        }

                        // Read the TLS bitmap

                        var tlsBitmap = _processContext.Process.ReadStruct<RtlBitmap64>(tlsBitmapAddress);
                        var tlsVectorSize = Unsafe.SizeOf<TlsVector64>() + sizeof(long) * tlsBitmap.SizeOfBitmap;

                        // Allocate a new TLS vector buffer for the thread

                        var newTlsVectorAddress = UnsafeHelpers.WrapPointer(_processContext.CallRoutine<long>(_processContext.GetFunctionAddress("kernel32.dll", "HeapAlloc"), processHeapAddress, HeapAllocationType.ZeroMemory, tlsVectorSize));

                        if (newTlsVectorAddress == IntPtr.Zero)
                        {
                            throw new ApplicationException("Failed to allocate a new TLS vector buffer in the process");
                        }

                        newTlsVectorAddresses.Add(newTlsVectorAddress);
                    }

                    // Ensure enough buffers were allocated

                    pebLock = new SafePebLock(_processContext);
                    _processContext.Process.Refresh();

                    if (_processContext.Process.Threads.Count <= tlsDataAddresses.Count)
                    {
                        break;
                    }

                    pebLock.Dispose();
                }
            }

            try
            {
                using (pebLock)
                {
                    if (_processContext.Process.GetArchitecture() == Architecture.X86)
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

                        var tlsEntryAddress = _processContext.Process.AllocateBuffer(Unsafe.SizeOf<LdrpTlsEntry32>(), ProtectionType.ReadWrite);
                        var tlsEntry = new LdrpTlsEntry32(new ListEntry32(tlsListAddress.ToInt32(), tlsListHead.Blink), tlsDirectory, _tlsData.Index);

                        try
                        {
                            _processContext.Process.WriteStruct(tlsEntryAddress, tlsEntry);

                            // Add the TLS entry to the TLS list

                            if (tlsListAddress == tlsListTailAddress)
                            {
                                tlsListHead = new ListEntry32(tlsEntryAddress.ToInt32(), tlsEntryAddress.ToInt32());
                                _processContext.Process.WriteStruct(tlsListAddress, tlsListHead);
                            }

                            else
                            {
                                try
                                {
                                    var newTlsListHead = new ListEntry32(tlsListHead.Flink, tlsEntryAddress.ToInt32());
                                    _processContext.Process.WriteStruct(tlsListAddress, newTlsListHead);

                                    try
                                    {
                                        var newTlsListTail = new ListEntry32(tlsEntryAddress.ToInt32(), tlsListTail.Blink);
                                        _processContext.Process.WriteStruct(tlsListTailAddress, newTlsListTail);
                                    }

                                    catch
                                    {
                                        Executor.IgnoreExceptions(() => _processContext.Process.WriteStruct(tlsEntryAddress, tlsListHead));
                                        throw;
                                    }
                                }

                                catch
                                {
                                    Executor.IgnoreExceptions(() => _processContext.Process.WriteStruct(tlsEntryAddress, tlsListHead));
                                    throw;
                                }
                            }

                            // Read the TLS data

                            var tlsDataAddress = UnsafeHelpers.WrapPointer(tlsDirectory.StartAddressOfRawData);
                            var tlsData = _processContext.Process.ReadSpan<byte>(tlsDataAddress, tlsDirectory.EndAddressOfRawData - tlsDirectory.StartAddressOfRawData);

                            for (var threadIndex = 0; threadIndex < _processContext.Process.Threads.Count; threadIndex += 1)
                            {
                                var thread = _processContext.Process.Threads[threadIndex];

                                if (!thread.IsActive())
                                {
                                    continue;
                                }

                                // Read the thread TEB

                                var basicInformation = thread.QueryInformation<ThreadBasicInformation64>(ThreadInformationType.BasicInformation);
                                var tebAddress = UnsafeHelpers.WrapPointer(basicInformation.TebBaseAddress);
                                var teb = _processContext.Process.ReadStruct<Teb64>(tebAddress);

                                // Read the thread WOW64 TEB

                                var wow64TebAddress = tebAddress + teb.WowTebOffset;
                                var wow64Teb = _processContext.Process.ReadStruct<Teb32>(wow64TebAddress);

                                if (wow64Teb.ThreadLocalStoragePointer == 0)
                                {
                                    continue;
                                }

                                var tlsIndexArrayAddress = UnsafeHelpers.WrapPointer(wow64Teb.ThreadLocalStoragePointer);

                                if (_tlsData.AllocatedBitmap)
                                {
                                    var tlsBitmap = _processContext.Process.ReadStruct<RtlBitmap32>(tlsBitmapAddress);
                                    var newTlsVectorAddress = newTlsVectorAddresses[0];

                                    // Read the current TLS vector

                                    var currentTlsVectorAddress = UnsafeHelpers.WrapPointer(wow64Teb.ThreadLocalStoragePointer) - Unsafe.SizeOf<TlsVector32>();
                                    var currentTlsVector = _processContext.Process.ReadStruct<TlsVector32>(currentTlsVectorAddress);

                                    if (tlsBitmap.SizeOfBitmap - Constants.TlsBitmapSize > 0)
                                    {
                                        // Copy over the current TLS index array

                                        var currentTlsVectorArrayAddress = currentTlsVectorAddress + Unsafe.SizeOf<TlsVector32>();
                                        var currentTlsIndexArray = _processContext.Process.ReadSpan<int>(currentTlsVectorArrayAddress, tlsBitmap.SizeOfBitmap - Constants.TlsBitmapSize);
                                        _processContext.Process.WriteSpan(newTlsVectorAddress + Unsafe.SizeOf<TlsVector32>(), currentTlsIndexArray);
                                    }

                                    // Initialise the new TLS vector

                                    var newTlsVector = new TlsVector32(tlsBitmap.SizeOfBitmap, currentTlsVector.PreviousDeferredTlsVector);
                                    _processContext.Process.WriteStruct(newTlsVectorAddress, newTlsVector);

                                    // Update the WOW64 TEB TLS index array pointer

                                    var tebTlsIndexArrayAddress = wow64TebAddress + Marshal.OffsetOf<Teb32>("ThreadLocalStoragePointer").ToInt32();
                                    _processContext.Process.WriteStruct(tebTlsIndexArrayAddress, newTlsVectorAddress + Unsafe.SizeOf<TlsVector32>(), true);

                                    // Add the current TLS vector to the delayed reclaim table to ensure it isn't prematurely freed

                                    var currentReclaimEntryAddress = delayedTlsReclaimTableAddress + sizeof(int) * ((thread.Id >> 2) & 0xF);
                                    var currentReclaimEntry = _processContext.Process.ReadStruct<TlsReclaimTableEntry32>(currentReclaimEntryAddress);

                                    if (currentReclaimEntry.TlsVector != 0)
                                    {
                                        currentTlsVector = new TlsVector32(thread.Id, currentReclaimEntry.TlsVector);
                                        _processContext.Process.WriteStruct(currentTlsVectorAddress, currentTlsVector);
                                        currentReclaimEntry = new TlsReclaimTableEntry32(currentTlsVectorAddress.ToInt32());
                                        _processContext.Process.WriteStruct(currentReclaimEntryAddress, currentReclaimEntry);
                                    }

                                    tlsIndexArrayAddress = newTlsVectorAddress + Unsafe.SizeOf<TlsVector32>();
                                }

                                // Write the TLS data into the process heap

                                var threadTlsDataAddress = tlsDataAddresses[0];
                                _processContext.Process.WriteSpan(threadTlsDataAddress, tlsData);

                                // Write the TLS index into the TLS index array

                                var tlsIndexArrayIndexAddress = tlsIndexArrayAddress + sizeof(int) * _tlsData.Index;
                                _processContext.Process.WriteStruct(tlsIndexArrayIndexAddress, threadTlsDataAddress);

                                tlsDataAddresses.RemoveAt(0);

                                if (_tlsData.AllocatedBitmap)
                                {
                                    newTlsVectorAddresses.RemoveAt(0);
                                }
                            }
                        }

                        catch
                        {
                            Executor.IgnoreExceptions(() => _processContext.Process.FreeBuffer(tlsEntryAddress));
                            throw;
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

                        // Write a TLS entry for the DLL into the process

                        var tlsEntryAddress = _processContext.Process.AllocateBuffer(Unsafe.SizeOf<LdrpTlsEntry64>(), ProtectionType.ReadWrite);
                        var tlsEntry = new LdrpTlsEntry64(new ListEntry64(tlsListAddress.ToInt64(), tlsListHead.Blink), tlsDirectory, _tlsData.Index);

                        try
                        {
                            _processContext.Process.WriteStruct(tlsEntryAddress, tlsEntry);

                            // Add the TLS entry to the TLS list

                            if (tlsListAddress == tlsListTailAddress)
                            {
                                tlsListHead = new ListEntry64(tlsEntryAddress.ToInt64(), tlsEntryAddress.ToInt64());
                                _processContext.Process.WriteStruct(tlsListAddress, tlsListHead);
                            }

                            else
                            {
                                try
                                {
                                    var newTlsListHead = new ListEntry64(tlsListHead.Flink, tlsEntryAddress.ToInt64());
                                    _processContext.Process.WriteStruct(tlsListAddress, newTlsListHead);

                                    try
                                    {
                                        var newTlsListTail = new ListEntry64(tlsEntryAddress.ToInt64(), tlsListTail.Blink);
                                        _processContext.Process.WriteStruct(tlsListTailAddress, newTlsListTail);
                                    }

                                    catch
                                    {
                                        Executor.IgnoreExceptions(() => _processContext.Process.WriteStruct(tlsEntryAddress, tlsListHead));
                                        throw;
                                    }
                                }

                                catch
                                {
                                    Executor.IgnoreExceptions(() => _processContext.Process.WriteStruct(tlsEntryAddress, tlsListHead));
                                    throw;
                                }
                            }

                            // Read the TLS data

                            var tlsDataAddress = UnsafeHelpers.WrapPointer(tlsDirectory.StartAddressOfRawData);
                            var tlsData = _processContext.Process.ReadSpan<byte>(tlsDataAddress, (int) (tlsDirectory.EndAddressOfRawData - tlsDirectory.StartAddressOfRawData));

                            for (var threadIndex = 0; threadIndex < _processContext.Process.Threads.Count; threadIndex += 1)
                            {
                                var thread = _processContext.Process.Threads[threadIndex];

                                if (!thread.IsActive())
                                {
                                    continue;
                                }

                                // Read the thread TEB

                                var basicInformation = thread.QueryInformation<ThreadBasicInformation64>(ThreadInformationType.BasicInformation);
                                var tebAddress = UnsafeHelpers.WrapPointer(basicInformation.TebBaseAddress);
                                var teb = _processContext.Process.ReadStruct<Teb64>(tebAddress);

                                if (teb.ThreadLocalStoragePointer == 0)
                                {
                                    continue;
                                }

                                var tlsIndexArrayAddress = UnsafeHelpers.WrapPointer(teb.ThreadLocalStoragePointer);

                                if (_tlsData.AllocatedBitmap)
                                {
                                    var tlsBitmap = _processContext.Process.ReadStruct<RtlBitmap64>(tlsBitmapAddress);
                                    var newTlsVectorAddress = newTlsVectorAddresses[0];

                                    // Read the current TLS vector

                                    var currentTlsVectorAddress = UnsafeHelpers.WrapPointer(teb.ThreadLocalStoragePointer) - Unsafe.SizeOf<TlsVector64>();
                                    var currentTlsVector = _processContext.Process.ReadStruct<TlsVector64>(currentTlsVectorAddress);

                                    if (tlsBitmap.SizeOfBitmap - Constants.TlsBitmapSize > 0)
                                    {
                                        // Copy over the current TLS index array

                                        var currentTlsVectorArrayAddress = currentTlsVectorAddress + Unsafe.SizeOf<TlsVector64>();
                                        var currentTlsIndexArray = _processContext.Process.ReadSpan<long>(currentTlsVectorArrayAddress, tlsBitmap.SizeOfBitmap - Constants.TlsBitmapSize);
                                        _processContext.Process.WriteSpan(newTlsVectorAddress + Unsafe.SizeOf<TlsVector64>(), currentTlsIndexArray);
                                    }

                                    // Initialise the new TLS vector

                                    var newTlsVector = new TlsVector64(tlsBitmap.SizeOfBitmap, currentTlsVector.PreviousDeferredTlsVector);
                                    _processContext.Process.WriteStruct(newTlsVectorAddress, newTlsVector);

                                    // Update the TEB TLS index array pointer

                                    var tebTlsIndexArrayAddress = tebAddress + Marshal.OffsetOf<Teb64>("ThreadLocalStoragePointer").ToInt32();
                                    _processContext.Process.WriteStruct(tebTlsIndexArrayAddress, newTlsVectorAddress + Unsafe.SizeOf<TlsVector64>(), true);

                                    // Add the current TLS vector to the delayed reclaim table to ensure it isn't prematurely freed

                                    var currentReclaimEntryAddress = delayedTlsReclaimTableAddress + sizeof(long) * ((thread.Id >> 2) & 0xF);
                                    var currentReclaimEntry = _processContext.Process.ReadStruct<TlsReclaimTableEntry64>(currentReclaimEntryAddress);

                                    if (currentReclaimEntry.TlsVector != 0)
                                    {
                                        currentTlsVector = new TlsVector64(thread.Id, currentReclaimEntry.TlsVector);
                                        _processContext.Process.WriteStruct(currentTlsVectorAddress, currentTlsVector);
                                        currentReclaimEntry = new TlsReclaimTableEntry64(currentTlsVectorAddress.ToInt64());
                                        _processContext.Process.WriteStruct(currentReclaimEntryAddress, currentReclaimEntry);
                                    }

                                    tlsIndexArrayAddress = newTlsVectorAddress + Unsafe.SizeOf<TlsVector64>();
                                }

                                // Write the TLS data into the process heap

                                var threadTlsDataAddress = tlsDataAddresses[0];
                                _processContext.Process.WriteSpan(threadTlsDataAddress, tlsData);

                                // Write the TLS index into the TLS index array

                                var tlsIndexArrayIndexAddress = tlsIndexArrayAddress + sizeof(long) * _tlsData.Index;
                                _processContext.Process.WriteStruct(tlsIndexArrayIndexAddress, threadTlsDataAddress);

                                tlsDataAddresses.RemoveAt(0);

                                if (_tlsData.AllocatedBitmap)
                                {
                                    newTlsVectorAddresses.RemoveAt(0);
                                }
                            }
                        }

                        catch
                        {
                            Executor.IgnoreExceptions(() => _processContext.Process.FreeBuffer(tlsEntryAddress));
                            throw;
                        }
                    }
                }
            }

            finally
            {
                // Free unused buffers

                foreach (var address in tlsDataAddresses)
                {
                    Executor.IgnoreExceptions(() => _processContext.CallRoutine(_processContext.GetFunctionAddress("kernel32.dll", "HeapFree"), processHeapAddress, 0, address));
                }

                foreach (var address in newTlsVectorAddresses)
                {
                    Executor.IgnoreExceptions(() => _processContext.CallRoutine(_processContext.GetFunctionAddress("kernel32.dll", "HeapFree"), processHeapAddress, 0, address));
                }
            }
        }

        private void InsertExceptionHandlers()
        {
            using var pebLock = new SafePebLock(_processContext);

            // Read the function table

            var functionTableAddress = _processContext.GetNtdllSymbolAddress("LdrpInvertedFunctionTable");
            var functionTable = _processContext.Process.ReadStruct<InvertedFunctionTable>(functionTableAddress);

            if (functionTable.Overflow == 1)
            {
                return;
            }

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

                while (insertionIndex < functionTable.Count)
                {
                    if ((uint) DllBaseAddress.ToInt32() < (uint) functionTableEntryList[insertionIndex].ImageBase)
                    {
                        break;
                    }

                    insertionIndex += 1;
                }

                if (insertionIndex < functionTable.Count)
                {
                    // Shift the existing elements to make space for the entry for the DLL

                    for (var entryIndex = functionTable.Count - 1; entryIndex >= insertionIndex; entryIndex -= 1)
                    {
                        functionTableEntryList[entryIndex + 1] = functionTableEntryList[entryIndex];
                    }
                }

                // Read the shared user data

                var sharedUserDataAddress = UnsafeHelpers.WrapPointer(Constants.SharedUserDataAddress);
                var sharedUserData = _processContext.Process.ReadStruct<KUserSharedData>(sharedUserDataAddress);

                // Encode the address of the exception directory using the system pointer encoding algorithm

                var exceptionDirectoryAddress = DllBaseAddress + loadConfigData.ExceptionTable!.RelativeAddress;
                var xoredAddress = (uint) exceptionDirectoryAddress.ToInt32() ^ (uint) sharedUserData.Cookie;
                var lowerCookieBits = sharedUserData.Cookie & 0x1F;
                var rotatedAddress = (xoredAddress >> lowerCookieBits) | (xoredAddress << (32 - lowerCookieBits));

                // Update the function table entry list

                functionTableEntryList[insertionIndex] = new InvertedFunctionTableEntry32((int) rotatedAddress, DllBaseAddress.ToInt32(), _peImage.Headers.PEHeader!.SizeOfImage, loadConfigData.ExceptionTable!.HandlerCount);
                _processContext.Process.WriteSpan(functionTableEntryListAddress, functionTableEntryList);
            }

            else
            {
                // Read the function table entry list

                var functionTableEntryListAddress = functionTableAddress + Unsafe.SizeOf<InvertedFunctionTable>();
                var functionTableEntryList = _processContext.Process.ReadSpan<InvertedFunctionTableEntry64>(functionTableEntryListAddress, Constants.InvertedFunctionTableSize);

                // Find the index where the entry for the DLL should be inserted

                var insertionIndex = 1;

                while (insertionIndex < functionTable.Count)
                {
                    if ((ulong) DllBaseAddress.ToInt64() < (ulong) functionTableEntryList[insertionIndex].ImageBase)
                    {
                        break;
                    }

                    insertionIndex += 1;
                }

                if (insertionIndex < functionTable.Count)
                {
                    // Shift the existing elements to make space for the entry for the DLL

                    for (var entryIndex = functionTable.Count - 1; entryIndex >= insertionIndex; entryIndex -= 1)
                    {
                        functionTableEntryList[entryIndex + 1] = functionTableEntryList[entryIndex];
                    }
                }

                // Update the function table entry list

                var exceptionDirectoryAddress = DllBaseAddress + _peImage.Headers.PEHeader!.ExceptionTableDirectory.RelativeVirtualAddress;
                functionTableEntryList[insertionIndex] = new InvertedFunctionTableEntry64(exceptionDirectoryAddress.ToInt64(), DllBaseAddress.ToInt64(), _peImage.Headers.PEHeader!.SizeOfImage, _peImage.Headers.PEHeader!.ExceptionTableDirectory.Size);
                _processContext.Process.WriteSpan(functionTableEntryListAddress, functionTableEntryList);
            }

            // Update the function table

            var overflow = functionTable.Count + 1 == functionTable.MaxCount ? 1 : 0;
            functionTable = new InvertedFunctionTable(functionTable.Count + 1, functionTable.MaxCount, overflow);
            _processContext.Process.WriteStruct(functionTableAddress, functionTable);
        }

        private void LoadDependencies()
        {
            var activationContext = new ActivationContext(_peImage.ResourceDirectory.GetManifest(), _processContext.Process.GetArchitecture());

            foreach (var (_, dependencyName) in _peImage.ImportDirectory.GetImportDescriptors())
            {
                // Write the dependency file path into the process

                var dependencyFilePath = _fileResolver.ResolveFilePath(_processContext.ResolveModuleName(dependencyName), activationContext);

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

                    _processContext.NotifyModuleLoad(dependencyAddress, dependencyFilePath);
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
            foreach (var sectionHeader in _peImage.Headers.SectionHeaders.Where(sectionHeader => !sectionHeader.SectionCharacteristics.HasFlag(SectionCharacteristics.MemDiscardable)))
            {
                if (sectionHeader.PointerToRawData == 0 || sectionHeader.SizeOfRawData == 0 && sectionHeader.VirtualSize == 0)
                {
                    continue;
                }

                // Calculate the raw section size

                var sectionSize = sectionHeader.SizeOfRawData;

                if (sectionHeader.SizeOfRawData > sectionHeader.VirtualSize)
                {
                    sectionSize = sectionHeader.VirtualSize;
                }

                // Map the raw section

                var sectionAddress = DllBaseAddress + sectionHeader.VirtualAddress;
                var sectionBytes = _dllBytes.Span.Slice(sectionHeader.PointerToRawData, sectionSize);
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
            using var pebLock = new SafePebLock(_processContext);

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

                var delta = (uint) DllBaseAddress.ToInt32() - (uint) _peImage.Headers.PEHeader!.ImageBase;

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

                var delta = (ulong) DllBaseAddress.ToInt64() - _peImage.Headers.PEHeader!.ImageBase;

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
            var processHeapAddress = _processContext.GetHeapAddress();
            var tlsBitmapAddress = _processContext.GetNtdllSymbolAddress("LdrpTlsBitmap");

            if (_processContext.Process.GetArchitecture() == Architecture.X86)
            {
                // Read the TLS bitmap

                var tlsBitmap = _processContext.Process.ReadStruct<RtlBitmap32>(tlsBitmapAddress);

                if (tlsBitmap.SizeOfBitmap == 0)
                {
                    tlsBitmap = new RtlBitmap32(Constants.TlsBitmapSize, initialTlsBitmapBufferAddress.ToInt32());

                    // Initialise the actual TLS bitmap size

                    _processContext.Process.WriteStruct(actualTlsBitmapSizeAddress, 1);
                }

                else
                {
                    // Try reserve an index in the TLS bitmap

                    _tlsData.Index = _processContext.CallRoutine<int>(_processContext.GetFunctionAddress("ntdll.dll", "RtlFindClearBitsAndSet"), tlsBitmapAddress, 1, 0);

                    if (_tlsData.Index != -1)
                    {
                        return;
                    }

                    // Check if the TLS bitmap buffer needs to be extended

                    var actualBitmapSize = _processContext.Process.ReadStruct<int>(actualTlsBitmapSizeAddress);
                    var actualBitmapSizeIncrement = (tlsBitmap.SizeOfBitmap + Constants.TlsBitmapIncrement32) >> 5;

                    if (actualBitmapSize < actualBitmapSizeIncrement)
                    {
                        // Allocate a new TLS bitmap buffer in the process heap

                        var newTlsBitmapBufferAddress = UnsafeHelpers.WrapPointer(_processContext.CallRoutine<int>(_processContext.GetFunctionAddress("kernel32.dll", "HeapAlloc"), processHeapAddress, HeapAllocationType.ZeroMemory, actualBitmapSizeIncrement));

                        if (newTlsBitmapBufferAddress == IntPtr.Zero)
                        {
                            throw new ApplicationException("Failed to allocate a new TLS bitmap buffer in the process");
                        }

                        try
                        {
                            // Copy over the current TLS bitmap buffer data

                            var currentTlsBitmapBufferAddress = UnsafeHelpers.WrapPointer(tlsBitmap.Buffer);
                            var currentTlsBitmapBufferSize = (tlsBitmap.SizeOfBitmap + 7) >> 3;
                            var currentTlsBitmapBuffer = _processContext.Process.ReadSpan<byte>(currentTlsBitmapBufferAddress, currentTlsBitmapBufferSize);
                            _processContext.Process.WriteSpan(newTlsBitmapBufferAddress, currentTlsBitmapBuffer);

                            if (currentTlsBitmapBufferAddress != initialTlsBitmapBufferAddress)
                            {
                                // Free the current TLS bitmap buffer

                                if (!_processContext.CallRoutine<bool>(_processContext.GetFunctionAddress("kernel32.dll", "HeapFree"), processHeapAddress, 0, currentTlsBitmapBufferAddress))
                                {
                                    throw new ApplicationException("Failed to free the TLS bitmap buffer in the process");
                                }
                            }

                            tlsBitmap = new RtlBitmap32(tlsBitmap.SizeOfBitmap + Constants.TlsBitmapSize, newTlsBitmapBufferAddress.ToInt32());

                            // Update the actual TLS bitmap size

                            _processContext.Process.WriteStruct(actualTlsBitmapSizeAddress, actualBitmapSizeIncrement);
                        }

                        catch
                        {
                            Executor.IgnoreExceptions(() => _processContext.CallRoutine(_processContext.GetFunctionAddress("kernel32.dll", "HeapFree"), processHeapAddress, 0, newTlsBitmapBufferAddress));
                            throw;
                        }
                    }

                    else
                    {
                        tlsBitmap = new RtlBitmap32(tlsBitmap.SizeOfBitmap + Constants.TlsBitmapSize, tlsBitmap.Buffer);
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
                    tlsBitmap = new RtlBitmap64(Constants.TlsBitmapSize, initialTlsBitmapBufferAddress.ToInt64());

                    // Initialise the actual TLS bitmap size

                    _processContext.Process.WriteStruct(actualTlsBitmapSizeAddress, 1);
                }

                else
                {
                    // Try reserve an index in the TLS bitmap

                    _tlsData.Index = _processContext.CallRoutine<int>(_processContext.GetFunctionAddress("ntdll.dll", "RtlFindClearBitsAndSet"), tlsBitmapAddress, 1, 0);

                    if (_tlsData.Index != -1)
                    {
                        return;
                    }

                    // Check if the TLS bitmap buffer needs to be extended

                    var actualBitmapSize = _processContext.Process.ReadStruct<int>(actualTlsBitmapSizeAddress);
                    var actualBitmapSizeIncrement = (tlsBitmap.SizeOfBitmap + Constants.TlsBitmapIncrement64) >> 5;

                    if (actualBitmapSize < actualBitmapSizeIncrement)
                    {
                        // Allocate a new TLS bitmap buffer in the process heap

                        var newTlsBitmapBufferAddress = UnsafeHelpers.WrapPointer(_processContext.CallRoutine<long>(_processContext.GetFunctionAddress("kernel32.dll", "HeapAlloc"), processHeapAddress, HeapAllocationType.ZeroMemory, actualBitmapSizeIncrement));

                        if (newTlsBitmapBufferAddress == IntPtr.Zero)
                        {
                            throw new ApplicationException("Failed to allocate a new TLS bitmap buffer in the process");
                        }

                        try
                        {
                            // Copy over the current TLS bitmap buffer data

                            var currentTlsBitmapBufferAddress = UnsafeHelpers.WrapPointer(tlsBitmap.Buffer);
                            var currentTlsBitmapBufferSize = (tlsBitmap.SizeOfBitmap + 7) >> 3;
                            var currentTlsBitmapBuffer = _processContext.Process.ReadSpan<byte>(currentTlsBitmapBufferAddress, currentTlsBitmapBufferSize);
                            _processContext.Process.WriteSpan(newTlsBitmapBufferAddress, currentTlsBitmapBuffer);

                            if (currentTlsBitmapBufferAddress != initialTlsBitmapBufferAddress)
                            {
                                // Free the current TLS bitmap buffer

                                if (!_processContext.CallRoutine<bool>(_processContext.GetFunctionAddress("kernel32.dll", "HeapFree"), processHeapAddress, 0, currentTlsBitmapBufferAddress))
                                {
                                    throw new ApplicationException("Failed to free the TLS bitmap buffer in the process");
                                }
                            }

                            tlsBitmap = new RtlBitmap64(tlsBitmap.SizeOfBitmap + Constants.TlsBitmapSize, newTlsBitmapBufferAddress.ToInt64());

                            // Update the actual TLS bitmap size

                            _processContext.Process.WriteStruct(actualTlsBitmapSizeAddress, actualBitmapSizeIncrement);
                        }

                        catch
                        {
                            Executor.IgnoreExceptions(() => _processContext.CallRoutine(_processContext.GetFunctionAddress("kernel32.dll", "HeapFree"), processHeapAddress, 0, newTlsBitmapBufferAddress));
                            throw;
                        }
                    }

                    else
                    {
                        tlsBitmap = new RtlBitmap64(tlsBitmap.SizeOfBitmap + Constants.TlsBitmapSize, tlsBitmap.Buffer);
                    }
                }

                // Update the TLS bitmap

                _processContext.Process.WriteStruct(tlsBitmapAddress, tlsBitmap);
            }

            _tlsData.AllocatedBitmap = true;

            // Reserve an index in the TLS bitmap

            _tlsData.Index = _processContext.CallRoutine<int>(_processContext.GetFunctionAddress("ntdll.dll", "RtlFindClearBitsAndSet"), tlsBitmapAddress, 1, 0);

            if (_tlsData.Index == -1)
            {
                throw new ApplicationException("Failed to reserve a TLS index in the TLS bitmap");
            }
        }

        private void RemoveExceptionHandlers()
        {
            using var pebLock = new SafePebLock(_processContext);

            // Read the function table

            var functionTableAddress = _processContext.GetNtdllSymbolAddress("LdrpInvertedFunctionTable");
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

                while (removalIndex < functionTable.Count)
                {
                    if (DllBaseAddress.ToInt32() == functionTableEntryList[removalIndex].ImageBase)
                    {
                        break;
                    }

                    removalIndex += 1;
                }

                if (removalIndex < functionTable.Count - 1)
                {
                    // Shift the existing elements to overwrite the entry for the DLL

                    for (var entryIndex = removalIndex; entryIndex < functionTable.Count; entryIndex += 1)
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

                while (removalIndex < functionTable.Count)
                {
                    if (DllBaseAddress.ToInt64() == functionTableEntryList[removalIndex].ImageBase)
                    {
                        break;
                    }

                    removalIndex += 1;
                }

                if (removalIndex < functionTable.Count - 1)
                {
                    // Shift the existing elements to overwrite the entry for the DLL

                    for (var entryIndex = removalIndex; entryIndex < functionTable.Count; entryIndex += 1)
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

            functionTable = new InvertedFunctionTable(functionTable.Count - 1, functionTable.MaxCount, 0);
            _processContext.Process.WriteStruct(functionTableAddress, functionTable);
        }
    }
}