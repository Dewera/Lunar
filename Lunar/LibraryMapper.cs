using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Lunar.Extensions;
using Lunar.Native;
using Lunar.Native.Enumerations;
using Lunar.Native.Structures;
using Lunar.Pdb;
using Lunar.PortableExecutable;
using Lunar.RemoteProcess;

[assembly: CLSCompliant(true)]

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

        private readonly Memory<byte> _dllBlock;

        private readonly MappingFlags _mappingFlags;

        private readonly PdbParser _pdbParser;

        private readonly PeImage _peImage;

        private readonly ProcessManager _processManager;

        /// <summary>
        /// Provides the functionality to map a DLL from memory into a process
        /// </summary>
        public LibraryMapper(Process process, Memory<byte> dllBlock, MappingFlags mappingFlags = MappingFlags.None)
        {
            if (process is null || process.HasExited)
            {
                throw new ArgumentException("The provided process is not currently running");
            }

            if (dllBlock.IsEmpty)
            {
                throw new ArgumentException("The provided DLL buffer was empty");
            }

            EnterDebugMode();

            _dllBlock = dllBlock.ToArray();

            _mappingFlags = mappingFlags;

            _pdbParser = new PdbParser(ResolveNtdllFilePath(process), "LdrpInvertedFunctionTable");

            _peImage = new PeImage(dllBlock);

            _processManager = new ProcessManager(process);
        }

        /// <summary>
        /// Provides the functionality to map a DLL from disk into a process
        /// </summary>
        public LibraryMapper(Process process, string dllFilePath, MappingFlags mappingFlags = MappingFlags.None)
        {
            if (process is null || process.HasExited)
            {
                throw new ArgumentException("The provided process is not currently running");
            }

            if (string.IsNullOrWhiteSpace(dllFilePath) || !File.Exists(dllFilePath))
            {
                throw new ArgumentException("The provided DLL file path did not point to a valid file");
            }

            EnterDebugMode();

            _dllBlock = File.ReadAllBytes(dllFilePath);

            _mappingFlags = mappingFlags;

            _pdbParser = new PdbParser(ResolveNtdllFilePath(process), "LdrpInvertedFunctionTable");

            _peImage = new PeImage(_dllBlock.ToArray());

            _processManager = new ProcessManager(process);
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

            DllBaseAddress = _processManager.Process.AllocateBuffer(_peImage.Headers.PEHeader.SizeOfImage);

            LoadDependencies();

            BuildImportAddressTable();

            RelocateImage();

            MapImage();

            InsertExceptionHandlers();

            InitialiseSecurityCookie();

            CallInitialisationRoutines(DllReason.ProcessAttach);
        }

        /// <summary>
        /// Unmaps the DLL from the process
        /// </summary>
        public void UnmapLibrary()
        {
            CallInitialisationRoutines(DllReason.ProcessDetach);

            RemoveExceptionHandlers();

            FreeDependencies();

            _processManager.Process.FreeBuffer(DllBaseAddress);

            DllBaseAddress = IntPtr.Zero;
        }

        private static void EnterDebugMode()
        {
            try
            {
                Process.EnterDebugMode();
            }

            catch (Win32Exception)
            {
                // The local process isn't running in administrator mode
            }
        }

        private static string ResolveNtdllFilePath(Process process)
        {
            if (process.GetArchitecture() == Architecture.X86 && Environment.Is64BitOperatingSystem)
            {
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), "ntdll.dll");
            }

            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ntdll.dll");
        }

        private void BuildImportAddressTable()
        {
            var importDescriptors = _peImage.ImportDirectory.ImportDescriptors.Concat(_peImage.DelayImportDirectory.DelayLoadImportDescriptors);

            Parallel.ForEach(importDescriptors, importDescriptor =>
            {
                foreach (var function in importDescriptor.Functions)
                {
                    // Write the address of the function into the import address table

                    IntPtr functionAddress;

                    if (function.Name is null)
                    {
                        functionAddress = _processManager.GetFunctionAddress(importDescriptor.Name, function.Ordinal);
                    }

                    else
                    {
                        functionAddress = _processManager.GetFunctionAddress(importDescriptor.Name, function.Name);
                    }

                    MemoryMarshal.Write(_dllBlock.Span.Slice(function.IatOffset), ref functionAddress);
                }
            });
        }

        private void CallInitialisationRoutines(DllReason reason)
        {
            if (_mappingFlags.HasFlag(MappingFlags.SkipInitialisationRoutines))
            {
                return;
            }

            // Call the entry point of any TLS callbacks

            foreach (var tlsCallBack in _peImage.TlsDirectory.TlsCallBacks)
            {
                var tlsCallBackAddress = DllBaseAddress + tlsCallBack.Rva;

                _processManager.CallRoutine(tlsCallBackAddress, DllBaseAddress, reason, 0);
            }

            // Call the entry point of the DLL

            if (_peImage.Headers.PEHeader.AddressOfEntryPoint == 0)
            {
                return;
            }

            var entryPointAddress = DllBaseAddress + _peImage.Headers.PEHeader.AddressOfEntryPoint;

            if (!_processManager.CallRoutine<bool>(entryPointAddress, DllBaseAddress, reason, 0))
            {
                throw new ApplicationException($"Failed to call the entry point of the DLL with {reason:G}");
            }
        }

        private void FreeDependencies()
        {
            var dependencies = _peImage.ImportDirectory.ImportDescriptors.Concat(_peImage.DelayImportDirectory.DelayLoadImportDescriptors);

            foreach (var dependency in dependencies)
            {
                // Unload the dependency using the Windows loader

                var routineAddress = _processManager.GetFunctionAddress("kernel32.dll", "FreeLibrary");

                var dependencyAddress = _processManager.GetModuleAddress(dependency.Name);

                if (!_processManager.CallRoutine<bool>(routineAddress, dependencyAddress))
                {
                    throw new ApplicationException("Failed to unload a dependency of the DLL");
                }
            }

            _processManager.Refresh();
        }

        private void InitialiseSecurityCookie()
        {
            if (_peImage.LoadConfigDirectory.SecurityCookie is null)
            {
                return;
            }

            // Generate a randomised security cookie

            Span<byte> securityCookieBlock = stackalloc byte[_processManager.Process.GetArchitecture() == Architecture.X86 ? 4 : 6];

            new Random().NextBytes(securityCookieBlock);

            // Ensure the default security cookie was not generated

            if (securityCookieBlock.SequenceEqual(stackalloc byte[] {0xBB, 0x40, 0xE6, 0x4E}) || securityCookieBlock.SequenceEqual(stackalloc byte[] {0x2B, 0x99, 0x2D, 0xDF, 0xA2, 0x32}))
            {
                securityCookieBlock[^1] += 1;
            }

            // Initialise the security cookie

            var securityCookieAddress = DllBaseAddress + _peImage.LoadConfigDirectory.SecurityCookie.Rva;

            _processManager.Process.WriteArray(securityCookieAddress, securityCookieBlock);
        }

        private void InsertExceptionHandlers()
        {
            // Read the inverted function table

            var functionTableAddress = _processManager.GetModuleAddress("ntdll.dll") + _pdbParser.GetSymbol("LdrpInvertedFunctionTable").Rva;

            var functionTable = _processManager.Process.ReadStructure<RtlInvertedFunctionTable>(functionTableAddress);

            if (functionTable.Overflow == 1)
            {
                return;
            }

            if (_processManager.Process.GetArchitecture() == Architecture.X86)
            {
                if (_peImage.LoadConfigDirectory.SehTable is null)
                {
                    return;
                }

                // Read the inverted function table entries

                var functionTableEntriesAddress = functionTableAddress + Unsafe.SizeOf<RtlInvertedFunctionTable>();

                var functionTableEntries = _processManager.Process.ReadArray<RtlInvertedFunctionTableEntry32>(functionTableEntriesAddress, Constants.InvertedFunctionTableEntryArraySize);

                // Determine where the new inverted function table entry should be inserted

                var insertionIndex = 1;

                while (insertionIndex < functionTable.Count)
                {
                    if (DllBaseAddress.ToInt32() < functionTableEntries[insertionIndex].ImageBase)
                    {
                        break;
                    }

                    insertionIndex += 1;
                }

                if (insertionIndex < functionTable.Count)
                {
                    // Shift the existing elements to make space for the new inverted function table entry

                    for (var entryIndex = functionTable.Count - 1; entryIndex >= insertionIndex; entryIndex -= 1)
                    {
                        functionTableEntries[entryIndex + 1] = functionTableEntries[entryIndex];
                    }
                }

                // Read the shared user data

                var sharedUserDataAddress = new IntPtr(Constants.SharedUserDataFixedAddress);

                var sharedUserData = _processManager.Process.ReadStructure<KUserSharedData>(sharedUserDataAddress);

                // Encode the address of the exception directory using the system pointer encoding algorithm

                var exceptionDirectoryAddress = DllBaseAddress + _peImage.LoadConfigDirectory.SehTable.Rva;

                var xoredAddress = exceptionDirectoryAddress.ToInt32() ^ sharedUserData.Cookie;

                var lowerCookieBits = sharedUserData.Cookie & 0x1F;

                var rotatedAddress = ((uint) xoredAddress >> lowerCookieBits) | ((uint) xoredAddress << (32 - lowerCookieBits));

                // Initialise a new function table entry for the DLL

                var newFunctionTableEntry = new RtlInvertedFunctionTableEntry32((int) rotatedAddress, DllBaseAddress.ToInt32(), _peImage.Headers.PEHeader.SizeOfImage, _peImage.LoadConfigDirectory.SehTable.HandlerCount);

                functionTableEntries[insertionIndex] = newFunctionTableEntry;

                // Update the existing inverted function table entries

                _processManager.Process.WriteArray(functionTableEntriesAddress, functionTableEntries);

                // Update the inverted function table

                var overflow = functionTable.Count + 1 == functionTable.MaxCount ? 1 : 0;

                var newFunctionTable = new RtlInvertedFunctionTable(functionTable.Count + 1, functionTable.MaxCount, overflow);

                try
                {
                    _processManager.Process.WriteStructure(functionTableAddress, newFunctionTable);
                }

                catch
                {
                    // Restore the original inverted function table entries

                    _processManager.Process.WriteArray(functionTableEntriesAddress, functionTableEntries);
                }
            }

            else
            {
                // Read the inverted function table entries

                var functionTableEntriesAddress = functionTableAddress + Unsafe.SizeOf<RtlInvertedFunctionTable>();

                var functionTableEntries = _processManager.Process.ReadArray<RtlInvertedFunctionTableEntry64>(functionTableEntriesAddress, Constants.InvertedFunctionTableEntryArraySize);

                // Determine where the new inverted function table entry should be inserted

                var insertionIndex = 1;

                while (insertionIndex < functionTable.Count)
                {
                    if (DllBaseAddress.ToInt64() < functionTableEntries[insertionIndex].ImageBase)
                    {
                        break;
                    }

                    insertionIndex += 1;
                }

                if (insertionIndex < functionTable.Count)
                {
                    // Shift the existing elements to make space for the new inverted function table entry

                    for (var entryIndex = functionTable.Count - 1; entryIndex >= insertionIndex; entryIndex -= 1)
                    {
                        functionTableEntries[entryIndex + 1] = functionTableEntries[entryIndex];
                    }
                }

                // Initialise a new function table entry for the DLL

                var exceptionDirectoryAddress = DllBaseAddress + _peImage.Headers.PEHeader.ExceptionTableDirectory.RelativeVirtualAddress;

                var newFunctionTableEntry = new RtlInvertedFunctionTableEntry64(exceptionDirectoryAddress.ToInt64(), DllBaseAddress.ToInt64(), _peImage.Headers.PEHeader.SizeOfImage, _peImage.Headers.PEHeader.ExceptionTableDirectory.Size);

                functionTableEntries[insertionIndex] = newFunctionTableEntry;

                // Update the existing inverted function table entries

                _processManager.Process.WriteArray(functionTableEntriesAddress, functionTableEntries);

                // Update the inverted function table

                var overflow = functionTable.Count + 1 == functionTable.MaxCount ? 1 : 0;

                var newFunctionTable = new RtlInvertedFunctionTable(functionTable.Count + 1, functionTable.MaxCount, overflow);

                try
                {
                    _processManager.Process.WriteStructure(functionTableAddress, newFunctionTable);
                }

                catch
                {
                    // Restore the original inverted function table entries

                    _processManager.Process.WriteArray(functionTableEntriesAddress, functionTableEntries);
                }
            }
        }

        private void LoadDependencies()
        {
            var dependencies = _peImage.ImportDirectory.ImportDescriptors.Concat(_peImage.DelayImportDirectory.DelayLoadImportDescriptors);

            foreach (var dependency in dependencies)
            {
                // Write the name of the dependency into a buffer

                var resolvedDependencyName = _processManager.ResolveModuleName(dependency.Name);

                var dependencyNameBlock = Encoding.Unicode.GetBytes(resolvedDependencyName);

                var dependencyNameBuffer = _processManager.Process.AllocateBuffer(dependencyNameBlock.Length);

                try
                {
                    _processManager.Process.WriteArray(dependencyNameBuffer, new Span<byte>(dependencyNameBlock));

                    // Load the dependency using the Windows loader

                    var routineAddress = _processManager.GetFunctionAddress("kernel32.dll", "LoadLibraryW");

                    var dependencyAddress = _processManager.CallRoutine<IntPtr>(routineAddress, dependencyNameBuffer);

                    if (dependencyAddress == IntPtr.Zero)
                    {
                        throw new ApplicationException("Failed to load a dependency of the DLL");
                    }
                }

                finally
                {
                    _processManager.Process.FreeBuffer(dependencyNameBuffer);
                }
            }

            _processManager.Refresh();
        }

        private void MapImage()
        {
            if (!_mappingFlags.HasFlag(MappingFlags.DiscardHeaders))
            {
                // Map the headers

                var headerBlock = _dllBlock.Span.Slice(0, _peImage.Headers.PEHeader.SizeOfHeaders);

                _processManager.Process.WriteArray(DllBaseAddress, headerBlock);

                _processManager.Process.ProtectBuffer(DllBaseAddress, _peImage.Headers.PEHeader.SizeOfHeaders, ProtectionType.ReadOnly);
            }

            foreach (var section in _peImage.Headers.SectionHeaders.Where(section => !section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemDiscardable)))
            {
                if (section.SizeOfRawData == 0)
                {
                    continue;
                }

                // Map the section

                var sectionAddress = DllBaseAddress + section.VirtualAddress;

                var sectionBlock = _dllBlock.Span.Slice(section.PointerToRawData, section.SizeOfRawData);

                _processManager.Process.WriteArray(sectionAddress, sectionBlock);

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

                _processManager.Process.ProtectBuffer(sectionAddress, section.SizeOfRawData, sectionProtection);
            }
        }

        private void RelocateImage()
        {
            if (_processManager.Process.GetArchitecture() == Architecture.X86)
            {
                // Calculate the delta from the preferred base address

                var delta = DllBaseAddress.ToInt32() - (int) _peImage.Headers.PEHeader.ImageBase;

                Parallel.ForEach(_peImage.BaseRelocationDirectory.BaseRelocations, baseRelocation =>
                {
                    if (baseRelocation.Type != BaseRelocationType.HighLow)
                    {
                        return;
                    }

                    // Perform the relocation

                    var relocationValue = MemoryMarshal.Read<int>(_dllBlock.Span.Slice(baseRelocation.Offset)) + delta;

                    MemoryMarshal.Write(_dllBlock.Span.Slice(baseRelocation.Offset), ref relocationValue);
                });
            }

            else
            {
                // Calculate the delta from the preferred base address

                var delta = DllBaseAddress.ToInt64() - (long) _peImage.Headers.PEHeader.ImageBase;

                Parallel.ForEach(_peImage.BaseRelocationDirectory.BaseRelocations, baseRelocation =>
                {
                    if (baseRelocation.Type != BaseRelocationType.Dir64)
                    {
                        return;
                    }

                    // Perform the relocation

                    var relocationValue = MemoryMarshal.Read<long>(_dllBlock.Span.Slice(baseRelocation.Offset)) + delta;

                    MemoryMarshal.Write(_dllBlock.Span.Slice(baseRelocation.Offset), ref relocationValue);
                });
            }
        }

        private void RemoveExceptionHandlers()
        {
            // Read the inverted function table

            var functionTableAddress = _processManager.GetModuleAddress("ntdll.dll") + _pdbParser.GetSymbol("LdrpInvertedFunctionTable").Rva;

            var functionTable = _processManager.Process.ReadStructure<RtlInvertedFunctionTable>(functionTableAddress);

            if (_processManager.Process.GetArchitecture() == Architecture.X86)
            {
                if (_peImage.LoadConfigDirectory.SehTable is null)
                {
                    return;
                }

                // Read the inverted function table entries

                var functionTableEntriesAddress = functionTableAddress + Unsafe.SizeOf<RtlInvertedFunctionTable>();

                var functionTableEntries = _processManager.Process.ReadArray<RtlInvertedFunctionTableEntry32>(functionTableEntriesAddress, Constants.InvertedFunctionTableEntryArraySize);

                // Determine where the inverted function table entry should be removed

                var removalIndex = 1;

                while (removalIndex < functionTable.Count)
                {
                    if (DllBaseAddress.ToInt32() == functionTableEntries[removalIndex].ImageBase)
                    {
                        break;
                    }

                    removalIndex += 1;
                }

                // Shift the existing elements to overwrite the inverted function table entry

                if (removalIndex < functionTable.Count - 1)
                {
                    for (var entryIndex = removalIndex; entryIndex < functionTable.Count; entryIndex += 1)
                    {
                        functionTableEntries[entryIndex] = functionTableEntries[entryIndex + 1];
                    }
                }

                else
                {
                    functionTableEntries[removalIndex] = new RtlInvertedFunctionTableEntry32();
                }

                // Update the existing inverted function table entries

                _processManager.Process.WriteArray(functionTableEntriesAddress, functionTableEntries);

                // Update the inverted function table

                var newFunctionTable = new RtlInvertedFunctionTable(functionTable.Count - 1, functionTable.MaxCount, 0);

                try
                {
                    _processManager.Process.WriteStructure(functionTableAddress, newFunctionTable);
                }

                catch
                {
                    // Restore the original inverted function table entries

                    _processManager.Process.WriteArray(functionTableEntriesAddress, functionTableEntries);
                }
            }

            else
            {
                // Read the inverted function table entries

                var functionTableEntriesAddress = functionTableAddress + Unsafe.SizeOf<RtlInvertedFunctionTable>();

                var functionTableEntries = _processManager.Process.ReadArray<RtlInvertedFunctionTableEntry64>(functionTableEntriesAddress, Constants.InvertedFunctionTableEntryArraySize);

                // Determine where the inverted function table entry should be removed

                var removalIndex = 1;

                while (removalIndex < functionTable.Count)
                {
                    if (DllBaseAddress.ToInt64() == functionTableEntries[removalIndex].ImageBase)
                    {
                        break;
                    }

                    removalIndex += 1;
                }

                // Shift the existing elements to overwrite the inverted function table entry

                if (removalIndex < functionTable.Count - 1)
                {
                    for (var entryIndex = removalIndex; entryIndex < functionTable.Count; entryIndex += 1)
                    {
                        functionTableEntries[entryIndex] = functionTableEntries[entryIndex + 1];
                    }
                }

                else
                {
                    functionTableEntries[removalIndex] = new RtlInvertedFunctionTableEntry64();
                }

                // Update the existing inverted function table entries

                _processManager.Process.WriteArray(functionTableEntriesAddress, functionTableEntries);

                // Update the inverted function table

                var newFunctionTable = new RtlInvertedFunctionTable(functionTable.Count - 1, functionTable.MaxCount, 0);

                try
                {
                    _processManager.Process.WriteStructure(functionTableAddress, newFunctionTable);
                }

                catch
                {
                    // Restore the original inverted function table entries

                    _processManager.Process.WriteArray(functionTableEntriesAddress, functionTableEntries);
                }
            }
        }
    }
}