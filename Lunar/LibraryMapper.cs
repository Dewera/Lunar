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
            if (_peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.Size == 0)
            {
                return;
            }

            using var pebLock = new SafePebLock(_processContext);

            if (_processContext.Architecture == Architecture.X86)
            {
                // Read the TLS entry

                var tlsEntry = _processContext.Process.ReadStruct<LdrpTlsEntry32>(_tlsData.EntryAddress);

                // Remove the TLS entry from the TLS list

                var previousEntryAddress = UnsafeHelpers.WrapPointer(tlsEntry.EntryLinks.Blink);
                var previousEntry = _processContext.Process.ReadStruct<ListEntry32>(previousEntryAddress);
                previousEntry = new ListEntry32(tlsEntry.EntryLinks.Flink, previousEntry.Blink);
                _processContext.Process.WriteStruct(previousEntryAddress, previousEntry);

                var nextEntryAddress = UnsafeHelpers.WrapPointer(tlsEntry.EntryLinks.Flink);
                var nextEntry = _processContext.Process.ReadStruct<ListEntry32>(nextEntryAddress);
                nextEntry = new ListEntry32(nextEntry.Flink, tlsEntry.EntryLinks.Blink);
                _processContext.Process.WriteStruct(nextEntryAddress, nextEntry);
            }

            else
            {
                // Read the TLS entry

                var tlsEntry = _processContext.Process.ReadStruct<LdrpTlsEntry64>(_tlsData.EntryAddress);

                // Remove the TLS entry from the TLS list

                var previousEntryAddress = UnsafeHelpers.WrapPointer(tlsEntry.EntryLinks.Blink);
                var previousEntry = _processContext.Process.ReadStruct<ListEntry64>(previousEntryAddress);
                previousEntry = new ListEntry64(tlsEntry.EntryLinks.Flink, previousEntry.Blink);
                _processContext.Process.WriteStruct(previousEntryAddress, previousEntry);

                var nextEntryAddress = UnsafeHelpers.WrapPointer(tlsEntry.EntryLinks.Flink);
                var nextEntry = _processContext.Process.ReadStruct<ListEntry64>(nextEntryAddress);
                nextEntry = new ListEntry64(nextEntry.Flink, tlsEntry.EntryLinks.Blink);
                _processContext.Process.WriteStruct(nextEntryAddress, nextEntry);
            }

            // Free the TLS entry

            _processContext.Process.FreeBuffer(_tlsData.EntryAddress);
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

            // Update the check function pointer

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

            // Update the dispatch function pointer

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

            var tlsDirectoryAddress = DllBaseAddress + _peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.RelativeVirtualAddress;
            var tlsListAddress = _processContext.GetNtdllSymbolAddress("LdrpTlsList");
            using var pebLock = new SafePebLock(_processContext);

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

                _tlsData.EntryAddress = _processContext.Process.AllocateBuffer(Unsafe.SizeOf<LdrpTlsEntry32>(), ProtectionType.ReadWrite);
                var tlsEntry = new LdrpTlsEntry32(new ListEntry32(tlsListAddress.ToInt32(), tlsListHead.Blink), tlsDirectory, _tlsData.Index);

                try
                {
                    _processContext.Process.WriteStruct(_tlsData.EntryAddress, tlsEntry);

                    // Insert the TLS entry into the TLS list

                    if (tlsListAddress == tlsListTailAddress)
                    {
                        tlsListHead = new ListEntry32(_tlsData.EntryAddress.ToInt32(), _tlsData.EntryAddress.ToInt32());
                        _processContext.Process.WriteStruct(tlsListAddress, tlsListHead);
                    }

                    else
                    {
                        try
                        {
                            var newTlsListHead = new ListEntry32(tlsListHead.Flink, _tlsData.EntryAddress.ToInt32());
                            _processContext.Process.WriteStruct(tlsListAddress, newTlsListHead);

                            try
                            {
                                var newTlsListTail = new ListEntry32(_tlsData.EntryAddress.ToInt32(), tlsListTail.Blink);
                                _processContext.Process.WriteStruct(tlsListTailAddress, newTlsListTail);
                            }

                            catch
                            {
                                Executor.IgnoreExceptions(() => _processContext.Process.WriteStruct(_tlsData.EntryAddress, tlsListHead));
                                throw;
                            }
                        }

                        catch
                        {
                            Executor.IgnoreExceptions(() => _processContext.Process.WriteStruct(_tlsData.EntryAddress, tlsListHead));
                            throw;
                        }
                    }
                }

                catch
                {
                    Executor.IgnoreExceptions(() => _processContext.Process.FreeBuffer(_tlsData.EntryAddress));
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

                _tlsData.EntryAddress = _processContext.Process.AllocateBuffer(Unsafe.SizeOf<LdrpTlsEntry64>(), ProtectionType.ReadWrite);
                var tlsEntry = new LdrpTlsEntry64(new ListEntry64(tlsListAddress.ToInt64(), tlsListHead.Blink), tlsDirectory, _tlsData.Index);

                try
                {
                    _processContext.Process.WriteStruct(_tlsData.EntryAddress, tlsEntry);

                    // Insert the TLS entry into the TLS list

                    if (tlsListAddress == tlsListTailAddress)
                    {
                        tlsListHead = new ListEntry64(_tlsData.EntryAddress.ToInt64(), _tlsData.EntryAddress.ToInt64());
                        _processContext.Process.WriteStruct(tlsListAddress, tlsListHead);
                    }

                    else
                    {
                        try
                        {
                            var newTlsListHead = new ListEntry64(tlsListHead.Flink, _tlsData.EntryAddress.ToInt64());
                            _processContext.Process.WriteStruct(tlsListAddress, newTlsListHead);

                            try
                            {
                                var newTlsListTail = new ListEntry64(_tlsData.EntryAddress.ToInt64(), tlsListTail.Blink);
                                _processContext.Process.WriteStruct(tlsListTailAddress, newTlsListTail);
                            }

                            catch
                            {
                                Executor.IgnoreExceptions(() => _processContext.Process.WriteStruct(_tlsData.EntryAddress, tlsListHead));
                                throw;
                            }
                        }

                        catch
                        {
                            Executor.IgnoreExceptions(() => _processContext.Process.WriteStruct(_tlsData.EntryAddress, tlsListHead));
                            throw;
                        }
                    }
                }

                catch
                {
                    Executor.IgnoreExceptions(() => _processContext.Process.FreeBuffer(_tlsData.EntryAddress));
                    throw;
                }
            }
        }

        private void InsertExceptionHandlers()
        {
            var functionTableAddress = _processContext.GetNtdllSymbolAddress("LdrpInvertedFunctionTable");
            using var pebLock = new SafePebLock(_processContext);

            // Read the function table

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
            var activationContext = new ActivationContext(_peImage.ResourceDirectory.GetManifest(), _processContext.Architecture);

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
            if (_peImage.Headers.PEHeader!.ThreadLocalStorageTableDirectory.Size == 0)
            {
                return;
            }

            var tlsBitmapAddress = _processContext.GetNtdllSymbolAddress("LdrpTlsBitmap");
            using var pebLock = new SafePebLock(_processContext);

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

            if (_processContext.Architecture == Architecture.X86)
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
                        // Allocate an extended TLS bitmap buffer in the process heap

                        var newTlsBitmapBufferAddress = _processContext.CallRoutine<IntPtr>(_processContext.GetFunctionAddress("kernel32.dll", "HeapAlloc"), processHeapAddress, HeapAllocationType.ZeroMemory, actualBitmapSizeIncrement);

                        if (newTlsBitmapBufferAddress == IntPtr.Zero)
                        {
                            throw new ApplicationException("Failed to allocate an extended TLS bitmap buffer in the process");
                        }

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
                                throw new ApplicationException("Failed to free the old TLS bitmap buffer in the process");
                            }
                        }

                        tlsBitmap = new RtlBitmap32(tlsBitmap.SizeOfBitmap + Constants.TlsBitmapSize, newTlsBitmapBufferAddress.ToInt32());

                        // Update the actual TLS bitmap size

                        _processContext.Process.WriteStruct(actualTlsBitmapSizeAddress, actualBitmapSizeIncrement);
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

                        var newTlsBitmapBufferAddress = _processContext.CallRoutine<IntPtr>(_processContext.GetFunctionAddress("kernel32.dll", "HeapAlloc"), processHeapAddress, HeapAllocationType.ZeroMemory, actualBitmapSizeIncrement);

                        if (newTlsBitmapBufferAddress == IntPtr.Zero)
                        {
                            throw new ApplicationException("Failed to allocate an extended TLS bitmap buffer in the process");
                        }

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
                                throw new ApplicationException("Failed to free the old TLS bitmap buffer in the process");
                            }
                        }

                        tlsBitmap = new RtlBitmap64(tlsBitmap.SizeOfBitmap + Constants.TlsBitmapSize, newTlsBitmapBufferAddress.ToInt64());

                        // Update the actual TLS bitmap size

                        _processContext.Process.WriteStruct(actualTlsBitmapSizeAddress, actualBitmapSizeIncrement);
                    }

                    else
                    {
                        tlsBitmap = new RtlBitmap64(tlsBitmap.SizeOfBitmap + Constants.TlsBitmapSize, tlsBitmap.Buffer);
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
            var functionTableAddress = _processContext.GetNtdllSymbolAddress("LdrpInvertedFunctionTable");
            using var pebLock = new SafePebLock(_processContext);

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