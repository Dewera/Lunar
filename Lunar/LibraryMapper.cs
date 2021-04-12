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
using Lunar.Native.Enumerations;
using Lunar.Native.Structures;
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

            DllBaseAddress = _processContext.Memory.AllocateBuffer(_peImage.Headers.PEHeader!.SizeOfImage, ProtectionType.ReadOnly);

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
                Executor.IgnoreExceptions(() => _processContext.Memory.FreeBuffer(DllBaseAddress));

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
                _processContext.Memory.FreeBuffer(DllBaseAddress);
            }

            catch (Exception exception)
            {
                topLevelException ??= exception;
            }

            DllBaseAddress = IntPtr.Zero;

            if (topLevelException is not null)
            {
                throw topLevelException;
            }
        }

        private void BuildImportAddressTable()
        {
            Parallel.ForEach(_peImage.ImportDirectory.GetImportDescriptors(), importDescriptor =>
            {
                foreach (var function in importDescriptor.Functions)
                {
                    // Write the address of the function into the import address table

                    var functionAddress = function.Name is null ? _processContext.GetFunctionAddress(importDescriptor.Name, function.Ordinal) : _processContext.GetFunctionAddress(importDescriptor.Name, function.Name);

                    MemoryMarshal.Write(_dllBytes.Span[function.Offset..], ref functionAddress);
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
            foreach (var dependency in _peImage.ImportDirectory.GetImportDescriptors())
            {
                // Free the dependency using the Windows loader

                var dependencyAddress = _processContext.GetModuleAddress(dependency.Name);

                if (!_processContext.CallRoutine<bool>(_processContext.GetFunctionAddress("kernel32.dll", "FreeLibrary"), dependencyAddress))
                {
                    throw new ApplicationException($"Failed to free the dependency {dependency.Name} from the process");
                }
            }

            _processContext.ClearModuleCache();
        }

        private void InitialiseSecurityCookie()
        {
            var securityCookie = _peImage.LoadConfigDirectory.GetSecurityCookie();

            if (securityCookie is null)
            {
                return;
            }

            // Generate a randomised security cookie

            var securityCookieBytes = _processContext.Process.GetArchitecture() == Architecture.X86 ? stackalloc byte[4] : stackalloc byte[6];

            RandomNumberGenerator.Fill(securityCookieBytes);

            // Ensure the default security cookie was not generated

            if (securityCookieBytes.SequenceEqual(stackalloc byte[] {0xBB, 0x40, 0xE6, 0x4E}) || securityCookieBytes.SequenceEqual(stackalloc byte[] {0x2B, 0x99, 0x2D, 0xDF, 0xA2, 0x32}))
            {
                securityCookieBytes[^1] += 1;
            }

            // Initialise the security cookie

            var securityCookieAddress = DllBaseAddress + securityCookie.RelativeAddress;

            _processContext.Memory.WriteSpan(securityCookieAddress, securityCookieBytes);
        }

        private void InsertExceptionHandlers()
        {
            _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlAcquirePebLock"));

            try
            {
                // Read the function table

                var functionTableAddress = _processContext.GetNtdllSymbolAddress("LdrpInvertedFunctionTable");

                var functionTable = _processContext.Memory.ReadStructure<InvertedFunctionTable>(functionTableAddress);

                if (functionTable.Overflow == 1)
                {
                    return;
                }

                if (_processContext.Process.GetArchitecture() == Architecture.X86)
                {
                    var exceptionTable = _peImage.LoadConfigDirectory.GetExceptionTable();

                    if (exceptionTable is null)
                    {
                        return;
                    }

                    // Read the function table entry array

                    var functionTableEntryArrayAddress = functionTableAddress + Unsafe.SizeOf<InvertedFunctionTable>();

                    var functionTableEntryArray = _processContext.Memory.ReadSpan<InvertedFunctionTableEntry32>(functionTableEntryArrayAddress, Constants.InvertedFunctionTableSize);

                    // Determine the index where the entry for the DLL should be inserted

                    var insertionIndex = 1;

                    while (insertionIndex < functionTable.Count)
                    {
                        if ((uint) DllBaseAddress.ToInt32() < (uint) functionTableEntryArray[insertionIndex].ImageBase)
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
                            functionTableEntryArray[entryIndex + 1] = functionTableEntryArray[entryIndex];
                        }
                    }

                    // Read the shared user data

                    var sharedUserDataAddress = SafeHelpers.CreateSafePointer(Constants.SharedUserDataAddress);

                    var sharedUserData = _processContext.Memory.ReadStructure<KUserSharedData>(sharedUserDataAddress);

                    // Encode the address of the exception directory using the system pointer encoding algorithm

                    var exceptionDirectoryAddress = DllBaseAddress + exceptionTable.RelativeAddress;

                    var xoredAddress = (uint) exceptionDirectoryAddress.ToInt32() ^ (uint) sharedUserData.Cookie;

                    var lowerCookieBits = sharedUserData.Cookie & 0x1F;

                    var rotatedAddress = (xoredAddress >> lowerCookieBits) | (xoredAddress << (32 - lowerCookieBits));

                    // Update the function table entry array

                    functionTableEntryArray[insertionIndex] = new InvertedFunctionTableEntry32((int) rotatedAddress, DllBaseAddress.ToInt32(), _peImage.Headers.PEHeader!.SizeOfImage, exceptionTable.HandlerCount);

                    _processContext.Memory.WriteSpan(functionTableEntryArrayAddress, functionTableEntryArray);
                }

                else
                {
                    // Read the function table entry array

                    var functionTableEntryArrayAddress = functionTableAddress + Unsafe.SizeOf<InvertedFunctionTable>();

                    var functionTableEntryArray = _processContext.Memory.ReadSpan<InvertedFunctionTableEntry64>(functionTableEntryArrayAddress, Constants.InvertedFunctionTableSize);

                    // Determine the index where the entry for the DLL should be inserted

                    var insertionIndex = 1;

                    while (insertionIndex < functionTable.Count)
                    {
                        if ((ulong) DllBaseAddress.ToInt64() < (ulong) functionTableEntryArray[insertionIndex].ImageBase)
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
                            functionTableEntryArray[entryIndex + 1] = functionTableEntryArray[entryIndex];
                        }
                    }

                    // Update the function table entry array

                    var exceptionDirectoryAddress = DllBaseAddress + _peImage.Headers.PEHeader!.ExceptionTableDirectory.RelativeVirtualAddress;

                    functionTableEntryArray[insertionIndex] = new InvertedFunctionTableEntry64(exceptionDirectoryAddress.ToInt64(), DllBaseAddress.ToInt64(), _peImage.Headers.PEHeader!.SizeOfImage, _peImage.Headers.PEHeader!.ExceptionTableDirectory.Size);

                    _processContext.Memory.WriteSpan(functionTableEntryArrayAddress, functionTableEntryArray);
                }

                // Update the function table

                var overflow = functionTable.Count + 1 == functionTable.MaxCount ? 1 : 0;

                functionTable = new InvertedFunctionTable(functionTable.Count + 1, functionTable.MaxCount, overflow);

                _processContext.Memory.WriteStructure(functionTableAddress, functionTable);
            }

            finally
            {
                _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlReleasePebLock"));
            }
        }

        private void LoadDependencies()
        {
            var activationContext = new ActivationContext(_peImage.ResourceDirectory.GetManifest(), _processContext.Process);

            foreach (var dependency in _peImage.ImportDirectory.GetImportDescriptors())
            {
                // Write the file path of the dependency into the process

                var dependencyFilePath = _fileResolver.ResolveFilePath(activationContext, _processContext.ResolveModuleName(dependency.Name));

                if (dependencyFilePath is null)
                {
                    throw new FileNotFoundException($"Failed to resolve the file path of the dependency {dependency.Name}");
                }

                var dependencyFilePathAddress = _processContext.Memory.AllocateBuffer(Encoding.Unicode.GetByteCount(dependencyFilePath), ProtectionType.ReadOnly);

                try
                {
                    _processContext.Memory.WriteString(dependencyFilePathAddress, dependencyFilePath);

                    // Load the dependency using the Windows loader

                    var dependencyAddress = _processContext.CallRoutine<IntPtr>(_processContext.GetFunctionAddress("kernel32.dll", "LoadLibraryW"), dependencyFilePathAddress);

                    if (dependencyAddress == IntPtr.Zero)
                    {
                        throw new ApplicationException($"Failed to load the dependency {dependency.Name} into the process");
                    }

                    _processContext.NotifyModuleLoad(dependencyAddress, dependencyFilePath);
                }

                finally
                {
                    _processContext.Memory.FreeBuffer(dependencyFilePathAddress);
                }
            }
        }

        private void MapHeaders()
        {
            // Map the headers

            var headerBytes = _dllBytes.Span[.._peImage.Headers.PEHeader!.SizeOfHeaders];

            _processContext.Memory.WriteSpan(DllBaseAddress, headerBytes);
        }

        private void MapSections()
        {
            foreach (var section in _peImage.Headers.SectionHeaders.Where(section => !section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemDiscardable)))
            {
                if (section.SizeOfRawData == 0)
                {
                    continue;
                }

                // Map the section

                var sectionAddress = DllBaseAddress + section.VirtualAddress;

                var sectionBytes = _dllBytes.Span.Slice(section.PointerToRawData, section.SizeOfRawData);

                _processContext.Memory.WriteSpan(sectionAddress, sectionBytes);

                // Determine the protection to apply to the section

                ProtectionType sectionProtection;

                if (section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemExecute))
                {
                    if (section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                    {
                        sectionProtection = section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ExecuteReadWrite : ProtectionType.ExecuteWriteCopy;
                    }

                    else
                    {
                        sectionProtection = section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ExecuteRead : ProtectionType.Execute;
                    }
                }

                else if (section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                {
                    sectionProtection = section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ReadWrite : ProtectionType.WriteCopy;
                }

                else
                {
                    sectionProtection = section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ReadOnly : ProtectionType.NoAccess;
                }

                if (section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemNotCached))
                {
                    sectionProtection |= ProtectionType.NoCache;
                }

                _processContext.Memory.ProtectBuffer(sectionAddress, section.SizeOfRawData, sectionProtection);
            }
        }

        private void RelocateImage()
        {
            Parallel.ForEach(_peImage.RelocationDirectory.GetRelocations(), relocation =>
            {
                switch (relocation.Type)
                {
                    case RelocationType.Dir64:
                    {
                        // Calculate the delta from the preferred base address

                        var delta = (ulong) DllBaseAddress.ToInt64() - _peImage.Headers.PEHeader!.ImageBase;

                        // Perform the relocation

                        var relocationValue = MemoryMarshal.Read<ulong>(_dllBytes.Span[relocation.Offset..]) + delta;

                        MemoryMarshal.Write(_dllBytes.Span[relocation.Offset..], ref relocationValue);

                        break;
                    }

                    case RelocationType.HighLow:
                    {
                        // Calculate the delta from the preferred base address

                        var delta = (uint) DllBaseAddress.ToInt32() - (uint) _peImage.Headers.PEHeader!.ImageBase;

                        // Perform the relocation

                        var relocationValue = MemoryMarshal.Read<uint>(_dllBytes.Span[relocation.Offset..]) + delta;

                        MemoryMarshal.Write(_dllBytes.Span[relocation.Offset..], ref relocationValue);

                        break;
                    }

                    default:
                    {
                        return;
                    }
                }
            });
        }

        private void RemoveExceptionHandlers()
        {
            _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlAcquirePebLock"));

            try
            {
                // Read the function table

                var functionTableAddress = _processContext.GetNtdllSymbolAddress("LdrpInvertedFunctionTable");

                var functionTable = _processContext.Memory.ReadStructure<InvertedFunctionTable>(functionTableAddress);

                if (_processContext.Process.GetArchitecture() == Architecture.X86)
                {
                    var exceptionTable = _peImage.LoadConfigDirectory.GetExceptionTable();

                    if (exceptionTable is null)
                    {
                        return;
                    }

                    // Read the function table entry array

                    var functionTableEntryArrayAddress = functionTableAddress + Unsafe.SizeOf<InvertedFunctionTable>();

                    var functionTableEntryArray = _processContext.Memory.ReadSpan<InvertedFunctionTableEntry32>(functionTableEntryArrayAddress, Constants.InvertedFunctionTableSize);

                    // Determine the index where the entry for the DLL should be removed

                    var removalIndex = 1;

                    while (removalIndex < functionTable.Count)
                    {
                        if (DllBaseAddress.ToInt32() == functionTableEntryArray[removalIndex].ImageBase)
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
                            functionTableEntryArray[entryIndex] = functionTableEntryArray[entryIndex + 1];
                        }
                    }

                    else
                    {
                        functionTableEntryArray[removalIndex] = default;
                    }

                    // Update the function table entry array

                    _processContext.Memory.WriteSpan(functionTableEntryArrayAddress, functionTableEntryArray);
                }

                else
                {
                    // Read the function table entry array

                    var functionTableEntryArrayAddress = functionTableAddress + Unsafe.SizeOf<InvertedFunctionTable>();

                    var functionTableEntryArray = _processContext.Memory.ReadSpan<InvertedFunctionTableEntry64>(functionTableEntryArrayAddress, Constants.InvertedFunctionTableSize);

                    // Determine the index where the entry for the DLL should be removed

                    var removalIndex = 1;

                    while (removalIndex < functionTable.Count)
                    {
                        if (DllBaseAddress.ToInt64() == functionTableEntryArray[removalIndex].ImageBase)
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
                            functionTableEntryArray[entryIndex] = functionTableEntryArray[entryIndex + 1];
                        }
                    }

                    else
                    {
                        functionTableEntryArray[removalIndex] = default;
                    }

                    // Update the function table entry array

                    _processContext.Memory.WriteSpan(functionTableEntryArrayAddress, functionTableEntryArray);
                }

                // Update the function table

                functionTable = new InvertedFunctionTable(functionTable.Count - 1, functionTable.MaxCount, 0);

                _processContext.Memory.WriteStructure(functionTableAddress, functionTable);
            }

            finally
            {
                _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlReleasePebLock"));
            }
        }
    }
}