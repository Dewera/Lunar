using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Extensions;
using Lunar.Native.Enumerations;
using Lunar.PortableExecutable;
using Lunar.PortableExecutable.Structures;
using Lunar.RemoteProcess;
using Lunar.Shared;
using Lunar.Symbol;

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

        private readonly Memory<byte> _dllBytes;

        private readonly PeImage _peImage;

        private readonly ProcessManager _processManager;

        private readonly SymbolParser _symbolParser;

        /// <summary>
        /// Provides the functionality to map a DLL from memory into a process
        /// </summary>
        public LibraryMapper(Process process, ReadOnlyMemory<byte> dllBytes)
        {
            // Validate the arguments

            if (process is null || process.HasExited)
            {
                throw new ArgumentException("The process provided was invalid");
            }

            if (dllBytes.IsEmpty)
            {
                throw new ArgumentException("The DLL bytes provided were invalid");
            }

            EnterDebugMode();

            _dllBytes = new Memory<byte>(new byte[dllBytes.Length]);

            dllBytes.CopyTo(_dllBytes);

            _peImage = new PeImage(dllBytes);

            _processManager = new ProcessManager(process);

            _symbolParser = new SymbolParser(RetrieveNtdllFilePath(process), "RtlInsertInvertedFunctionTable", "RtlRemoveInvertedFunctionTable");
        }

        /// <summary>
        /// Provides the functionality to map a DLL from disk into a process
        /// </summary>
        public LibraryMapper(Process process, string dllFilePath)
        {
            // Validate the arguments

            if (process is null || process.HasExited)
            {
                throw new ArgumentException("The process provided was invalid");
            }

            if (string.IsNullOrWhiteSpace(dllFilePath))
            {
                throw new ArgumentException("The DLL file path provided was invalid");
            }

            EnterDebugMode();

            var dllBytes = File.ReadAllBytes(dllFilePath);

            _dllBytes = new Memory<byte>(new byte[dllBytes.Length]);

            dllBytes.CopyTo(_dllBytes);

            _peImage = new PeImage(dllBytes);

            _processManager = new ProcessManager(process);

            _symbolParser = new SymbolParser(RetrieveNtdllFilePath(process), "RtlInsertInvertedFunctionTable", "RtlRemoveInvertedFunctionTable");
        }

        /// <summary>
        /// Maps the DLL into the process
        /// </summary>
        public void MapLibrary()
        {
            DllBaseAddress = _processManager.Process.AllocateMemory(_peImage.PeHeaders.PEHeader.SizeOfImage, ProtectionType.ReadWrite);

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

            UnloadDependencies();

            _processManager.Process.FreeMemory(DllBaseAddress);

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

        private static string RetrieveNtdllFilePath(Process process)
        {
            var systemFolderPath = Environment.GetFolderPath(process.GetArchitecture() == Architecture.X86 ? Environment.SpecialFolder.SystemX86 : Environment.SpecialFolder.System);

            return Path.Combine(systemFolderPath, "ntdll.dll");
        }

        private void BuildImportAddressTable()
        {
            var importDescriptors = _peImage.ImportDirectory.Value.ImportDescriptors.Concat(_peImage.DelayImportDirectory.Value.DelayImportDescriptors);

            foreach (var importDescriptor in importDescriptors)
            {
                var importDescriptorName = _processManager.ResolveDllName(importDescriptor.Name);

                foreach (var function in importDescriptor.Functions)
                {
                    // Write the function address into the import address table

                    var functionAddress = function.Name is null ? _processManager.GetFunctionAddress(importDescriptorName, function.Ordinal) : _processManager.GetFunctionAddress(importDescriptorName, function.Name);

                    MemoryMarshal.Write(_dllBytes.Slice(function.Offset).Span, ref functionAddress);
                }
            }
        }

        private void CallInitialisationRoutines(DllReason reason)
        {
            // Call the entry point of any TLS callbacks

            if (_peImage.TlsDirectory.Value.TlsCallbackOffsets.Any(tlsCallbackOffset => !_processManager.CallRoutine<bool>(CallingConvention.StdCall, DllBaseAddress + tlsCallbackOffset, DllBaseAddress.ToInt64(), (long) reason, 0)))
            {
                throw ExceptionBuilder.BuildRemoteRoutineCallException($"the entry point of a TLS callback with {reason:G}");
            }

            // Call the entry point of the DLL

            if (_peImage.PeHeaders.PEHeader.AddressOfEntryPoint != 0 && !_processManager.CallRoutine<bool>(CallingConvention.StdCall, DllBaseAddress + _peImage.PeHeaders.PEHeader.AddressOfEntryPoint, DllBaseAddress.ToInt64(), (long) reason, 0))
            {
                throw ExceptionBuilder.BuildRemoteRoutineCallException($"the entry point of the DLL with {reason:G}");
            }
        }

        private void InitialiseSecurityCookie()
        {
            if (_peImage.LoadConfigDirectory.Value.SecurityCookieOffset == 0)
            {
                return;
            }

            // Generate a randomised security cookie

            var securityCookieBytes = _processManager.Process.GetArchitecture() == Architecture.X86 ? new byte[4] : new byte[6];

            new Random().NextBytes(securityCookieBytes);

            // Ensure the default security cookie wasn't generated

            if (securityCookieBytes.SequenceEqual(new byte[] {0xBB, 0x40, 0xE6, 0x4E}) || securityCookieBytes.SequenceEqual(new byte[] {0x2B, 0x99, 0x2D, 0xDF, 0xA2, 0x32}))
            {
                securityCookieBytes[^1] += 1;
            }

            // Initialise the security cookie

            _processManager.Process.WriteMemory(DllBaseAddress + _peImage.LoadConfigDirectory.Value.SecurityCookieOffset, securityCookieBytes);
        }

        private void InsertExceptionHandlers()
        {
            // Insert the exception handlers for the DLL into the LdrpInvertedFunctionTable

            var routineAddress = _processManager.Modules.First(module => module.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase)).BaseAddress + _symbolParser.SymbolOffsets["RtlInsertInvertedFunctionTable"];

            if (!_processManager.CallRoutine<bool>(CallingConvention.FastCall, routineAddress, DllBaseAddress.ToInt64(), _peImage.PeHeaders.PEHeader.SizeOfImage))
            {
                throw ExceptionBuilder.BuildRemoteRoutineCallException("RtlInsertInvertedFunctionTable");
            }
        }

        private void LoadDependencies()
        {
            var systemFolderPath = Environment.GetFolderPath(_processManager.Process.GetArchitecture() == Architecture.X86 ? Environment.SpecialFolder.SystemX86 : Environment.SpecialFolder.System);

            var dependencies = _peImage.ImportDirectory.Value.ImportDescriptors.Concat(_peImage.DelayImportDirectory.Value.DelayImportDescriptors);

            foreach (var dependency in dependencies)
            {
                // Write the file path of the dependency into a buffer

                var dependencyFilePath = Path.Combine(systemFolderPath, _processManager.ResolveDllName(dependency.Name));

                var dependencyFilePathBytes = Encoding.Unicode.GetBytes(dependencyFilePath);

                var dependencyFilePathBuffer = _processManager.Process.AllocateMemory(dependencyFilePathBytes.Length, ProtectionType.ReadWrite);

                _processManager.Process.WriteMemory(dependencyFilePathBuffer, dependencyFilePathBytes);

                // Load the dependency using LoadLibrary

                var routineAddress = _processManager.GetFunctionAddress("kernel32.dll", "LoadLibraryW");

                var dependencyBaseAddress = _processManager.CallRoutine<IntPtr>(CallingConvention.StdCall, routineAddress, dependencyFilePathBuffer.ToInt64());

                if (dependencyBaseAddress == IntPtr.Zero)
                {
                    throw ExceptionBuilder.BuildRemoteRoutineCallException("LoadLibraryW");
                }
            }

            _processManager.RefreshModules();
        }

        private void MapImage()
        {
            // Map the image headers

            var imageHeaders = _dllBytes.Slice(0, _peImage.PeHeaders.PEHeader.SizeOfHeaders);

            _processManager.Process.WriteMemory(DllBaseAddress, imageHeaders);

            _processManager.Process.ProtectMemory(DllBaseAddress, imageHeaders.Length, ProtectionType.ReadOnly);

            // Map the image sections

            static ProtectionType DetermineSectionProtection(SectionCharacteristics sectionCharacteristics)
            {
                ProtectionType sectionProtection;

                if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemExecute))
                {
                    if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                    {
                        sectionProtection = ProtectionType.ExecuteReadWrite;
                    }

                    else
                    {
                        sectionProtection = sectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ExecuteRead : ProtectionType.Execute;
                    }
                }

                else if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                {
                    sectionProtection = ProtectionType.ReadWrite;
                }

                else
                {
                    sectionProtection = sectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ReadOnly : ProtectionType.NoAccess;
                }

                if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemNotCached))
                {
                    sectionProtection |= ProtectionType.NoCache;
                }

                return sectionProtection;
            }

            foreach (var section in _peImage.PeHeaders.SectionHeaders.Where(section => !section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemDiscardable)))
            {
                int sectionSize;

                if (section.SizeOfRawData == 0)
                {
                    if (section.SectionCharacteristics.HasFlag(SectionCharacteristics.ContainsInitializedData))
                    {
                        sectionSize = _peImage.PeHeaders.PEHeader.SizeOfInitializedData;
                    }

                    else if (section.SectionCharacteristics.HasFlag(SectionCharacteristics.ContainsUninitializedData))
                    {
                        sectionSize = _peImage.PeHeaders.PEHeader.SizeOfUninitializedData;
                    }

                    else
                    {
                        continue;
                    }
                }

                else
                {
                    sectionSize = section.SizeOfRawData;
                }

                var sectionAddress = DllBaseAddress + section.VirtualAddress;

                var sectionData = _dllBytes.Slice(section.PointerToRawData, sectionSize);

                _processManager.Process.WriteMemory(sectionAddress, sectionData);

                _processManager.Process.ProtectMemory(sectionAddress, sectionData.Length, DetermineSectionProtection(section.SectionCharacteristics));
            }
        }

        private void RelocateImage()
        {
            // Calculate the delta from the preferred base address

            var delta = DllBaseAddress.ToInt64() - (long) _peImage.PeHeaders.PEHeader.ImageBase;

            foreach (var relocation in _peImage.BaseRelocationDirectory.Value.BaseRelocations)
            {
                switch (relocation.Type)
                {
                    case BaseRelocationType.HighLow:
                    {
                        // Perform the relocation

                        var relocationValue = MemoryMarshal.Read<int>(_dllBytes.Slice(relocation.Offset).Span) + (int) delta;

                        MemoryMarshal.Write(_dllBytes.Slice(relocation.Offset).Span, ref relocationValue);

                        break;
                    }

                    case BaseRelocationType.Dir64:
                    {
                        // Perform the relocation

                        var relocationValue = MemoryMarshal.Read<long>(_dllBytes.Slice(relocation.Offset).Span) + delta;

                        MemoryMarshal.Write(_dllBytes.Slice(relocation.Offset).Span, ref relocationValue);

                        break;
                    }
                }
            }
        }

        private void RemoveExceptionHandlers()
        {
            // Remove the exception handlers for the DLL from the LdrpInvertedFunctionTable

            var routineAddress = _processManager.Modules.First(module => module.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase)).BaseAddress + _symbolParser.SymbolOffsets["RtlRemoveInvertedFunctionTable"];

            if (!_processManager.CallRoutine<bool>(CallingConvention.FastCall, routineAddress, DllBaseAddress.ToInt64()))
            {
                throw ExceptionBuilder.BuildRemoteRoutineCallException("RtlRemoveInvertedFunctionTable");
            }
        }

        private void UnloadDependencies()
        {
            var dependencies = _peImage.ImportDirectory.Value.ImportDescriptors.Concat(_peImage.DelayImportDirectory.Value.DelayImportDescriptors);

            foreach (var dependency in dependencies)
            {
                // Unload the dependency using FreeLibrary

                var dependencyAddress = _processManager.Modules.First(module => module.Name.Equals(_processManager.ResolveDllName(dependency.Name), StringComparison.OrdinalIgnoreCase)).BaseAddress;

                if (!_processManager.CallRoutine<bool>(CallingConvention.StdCall, _processManager.GetFunctionAddress("kernel32.dll", "FreeLibrary"), dependencyAddress.ToInt64()))
                {
                    throw ExceptionBuilder.BuildRemoteRoutineCallException("FreeLibrary");
                }
            }

            _processManager.RefreshModules();
        }
    }
}