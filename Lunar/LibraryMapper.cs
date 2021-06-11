using System;
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

        /// <summary>
        /// Initialises an instances of the <see cref="LibraryMapper"/> class with the functionality to map a DLL from memory into a process
        /// </summary>
        public LibraryMapper(Process process, Memory<byte> dllBytes, MappingFlags mappingFlags = MappingFlags.None)
        {
            if (process is null || process.HasExited)
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
            if (process is null || process.HasExited)
            {
                throw new ArgumentException("The provided process is not currently running");
            }

            if (string.IsNullOrWhiteSpace(dllFilePath) || !File.Exists(dllFilePath))
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

                    if (_mappingFlags.HasFlag(MappingFlags.SkipInitialisationRoutines))
                    {
                        return;
                    }

                    try
                    {
                        CallInitialisationRoutines(DllReason.ProcessAttach);
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
                    // Write the address of the function into the import address table

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

            // Call the entry point of the DLL

            var entryPointAddress = DllBaseAddress + _peImage.Headers.PEHeader!.AddressOfEntryPoint;

            if (!_processContext.CallRoutine<bool>(entryPointAddress, DllBaseAddress, reason, 0))
            {
                throw new ApplicationException($"Failed to call the entry point of the DLL with {reason:G}");
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

        private void InsertExceptionHandlers()
        {
            _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlAcquirePebLock"));

            try
            {
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

                    var sharedUserDataAddress = SafeHelpers.CreateSafePointer(Constants.SharedUserDataAddress);
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

            finally
            {
                _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlReleasePebLock"));
            }
        }

        private void LoadDependencies()
        {
            var activationContext = new ActivationContext(_processContext.Process.GetArchitecture(), _peImage.ResourceDirectory.GetManifest());

            foreach (var (_, dependencyName) in _peImage.ImportDirectory.GetImportDescriptors())
            {
                // Write the dependency file path into the process

                var dependencyFilePath = _fileResolver.ResolveFilePath(activationContext, _processContext.ResolveModuleName(dependencyName));

                if (dependencyFilePath is null)
                {
                    throw new FileNotFoundException($"Failed to resolve the file path of the dependency {dependencyName}");
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

        private void RemoveExceptionHandlers()
        {
            _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlAcquirePebLock"));

            try
            {
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

            finally
            {
                _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlReleasePebLock"));
            }
        }
    }
}