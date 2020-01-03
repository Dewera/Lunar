using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Native.Enumerations;
using Lunar.PortableExecutable;
using Lunar.RemoteProcess;
using Lunar.Symbol;

[assembly: CLSCompliant(true)]

namespace Lunar
{
    /// <summary>
    /// Provides the functionality to map a DLL from disk or memory into a remote process
    /// </summary>
    public sealed class LibraryMapper
    {
        /// <summary>
        /// The current base address of the DLL in the remote process
        /// </summary>
        public IntPtr DllBaseAddress { get; private set; }

        private readonly Memory<byte> _dllBytes;

        private readonly PeImage _peImage;

        private readonly ProcessManager _processManager;

        private readonly SymbolParser _symbolParser;

        /// <summary>
        /// Provides the functionality to map a DLL from memory into a remote process
        /// </summary>
        public LibraryMapper(Process process, Memory<byte> dllBytes)
        {
            // Validate the arguments passed into the constructor

            if (process == default || process.HasExited)
            {
                throw new ArgumentException("The process provided was invalid");
            }

            if (dllBytes.IsEmpty)
            {
                throw new ArgumentException("The DLL bytes provided were invalid");
            }

            EnterDebugMode();

            _dllBytes = dllBytes;

            _peImage = new PeImage(dllBytes);

            _processManager = new ProcessManager(process);

            _symbolParser = new SymbolParser(_processManager.Modules.First(module => module.Name.Equals("ntdll.dll")));

            ValidateArchitecture();
        }

        /// <summary>
        /// Provides the functionality to map a DLL from disk into a remote process
        /// </summary>
        public LibraryMapper(Process process, string dllPath)
        {
            // Validate the arguments passed into the constructor

            if (process == default || process.HasExited)
            {
                throw new ArgumentException("The process provided was invalid");
            }

            if (string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("The DLL path provided was invalid");
            }

            EnterDebugMode();

            _dllBytes = File.ReadAllBytes(dllPath);

            _peImage = new PeImage(_dllBytes);

            _processManager = new ProcessManager(process);

            _symbolParser = new SymbolParser(_processManager.Modules.First(module => module.Name.Equals("ntdll.dll")));

            ValidateArchitecture();
        }

        /// <summary>
        /// Maps the DLL into the remote process
        /// </summary>
        public void MapLibrary()
        {
            DllBaseAddress = _processManager.Memory.Allocate(_peImage.Headers.PEHeader.SizeOfImage, ProtectionType.ReadWrite);

            LoadDependencies();

            BuildImportAddressTable();

            RelocateImage();

            MapSections();

            MapHeaders();

            EnableExceptionHandling();

            InitialiseSecurityCookie();

            CallInitialisationRoutines(DllReason.ProcessAttach);
        }

        /// <summary>
        /// Unmaps the DLL from the remote process
        /// </summary>
        public void UnmapLibrary()
        {
            CallInitialisationRoutines(DllReason.ProcessDetach);

            DisableExceptionHandling();

            FreeDependencies();

            _processManager.Memory.Free(DllBaseAddress);

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

        private void BuildImportAddressTable()
        {
            if (_peImage.ImportDescriptors.Count == 0)
            {
                return;
            }

            foreach (var importDescriptor in _peImage.ImportDescriptors)
            {
                foreach (var function in importDescriptor.Functions)
                {
                    IntPtr functionAddress;

                    if (function.Name.Equals(string.Empty))
                    {
                        // Find the module that the function is exported from in the remote process

                        var functionModule = _processManager.Modules.First(module => module.Name.Equals(importDescriptor.Name, StringComparison.OrdinalIgnoreCase));

                        // Determine the name of the function using its ordinal

                        var functionName = functionModule.PeImage.Value.ExportedFunctions.First(exportedFunction => exportedFunction.Ordinal == function.Ordinal).Name;

                        functionAddress = _processManager.GetFunctionAddress(importDescriptor.Name, functionName);
                    }

                    else
                    {
                        functionAddress = _processManager.GetFunctionAddress(importDescriptor.Name, function.Name);
                    }

                    // Write the function address into the import address table in the local process

                    if (_processManager.IsWow64)
                    {
                        MemoryMarshal.Write(_dllBytes.Slice(function.Offset).Span, ref Unsafe.AsRef(functionAddress.ToInt32()));
                    }

                    else
                    {
                        MemoryMarshal.Write(_dllBytes.Slice(function.Offset).Span, ref Unsafe.AsRef(functionAddress.ToInt64()));
                    }
                }
            }
        }

        private void CallInitialisationRoutines(DllReason reason)
        {
            // Call any TLS callbacks

            if (_peImage.TlsCallbacks.Any(tlsCallback => !_processManager.CallFunction<bool>(CallingConvention.StdCall, DllBaseAddress + tlsCallback.Offset, DllBaseAddress.ToInt64(), (long) reason, 0)))
            {
                throw new Win32Exception($"Failed to call the entry point of a TLS callback with {reason.ToString()} in the remote process");
            }

            // Call the entry point of the DLL

            if (_peImage.Headers.PEHeader.AddressOfEntryPoint == 0)
            {
                return;
            }

            if (!_processManager.CallFunction<bool>(CallingConvention.StdCall, DllBaseAddress + _peImage.Headers.PEHeader.AddressOfEntryPoint, DllBaseAddress.ToInt64(), (long) reason, 0))
            {
                throw new Win32Exception($"Failed to call the entry point of the DLL with {reason.ToString()} in the remote process");
            }
        }

        private void DisableExceptionHandling()
        {
            // Remove the entry for the DLL from the LdrpInvertedFunctionTable

            if (!_processManager.CallFunction<bool>(CallingConvention.FastCall, _symbolParser.RtlRemoveInvertedFunctionTable, DllBaseAddress.ToInt64()))
            {
                throw new Win32Exception("Failed to call RtlRemoveInvertedFunctionTable in the remote process");
            }
        }

        private void EnableExceptionHandling()
        {
            // Add an entry for the DLL to the LdrpInvertedFunctionTable

            if (!_processManager.CallFunction<bool>(CallingConvention.FastCall, _symbolParser.RtlInsertInvertedFunctionTable, DllBaseAddress.ToInt64(), _peImage.Headers.PEHeader.SizeOfImage))
            {
                throw new Win32Exception("Failed to call RtlInsertInvertedFunctionTable in the remote process");
            }
        }

        private void FreeDependencies()
        {
            foreach (var importDescriptor in _peImage.ImportDescriptors)
            {
                // Get the base address of the dependency in the remote process

                var dependencyBaseAddress = _processManager.Modules.First(module => module.Name.Equals(importDescriptor.Name, StringComparison.OrdinalIgnoreCase)).BaseAddress;

                // Free the dependency from the remote process, decreasing its reference count if it is higher than 1

                if (!_processManager.CallFunction<bool>(CallingConvention.StdCall, _processManager.GetFunctionAddress("kernel32.dll", "FreeLibrary"), dependencyBaseAddress.ToInt64()))
                {
                    throw new Win32Exception("Failed to call FreeLibrary in the remote process");
                }
            }
        }

        private void InitialiseSecurityCookie()
        {
            if (_peImage.SecurityCookie.Offset == 0)
            {
                return;
            }

            // Generate a randomised security cookie, ensuring the default security cookie value is not generated

            byte[] securityCookieBytes;

            if (_processManager.IsWow64)
            {
                securityCookieBytes = new byte[4];

                new Random().NextBytes(securityCookieBytes);

                if (securityCookieBytes.SequenceEqual(new byte[] {0xBB, 0x40, 0xE6, 0x4E}))
                {
                    securityCookieBytes[3] += 1;
                }
            }

            else
            {
                var partialSecurityCookieBytes = new byte[6];

                new Random().NextBytes(partialSecurityCookieBytes);

                if (partialSecurityCookieBytes.SequenceEqual(new byte[] {0x2B, 0x99, 0x2D, 0xDF, 0xA2, 0x32}))
                {
                    partialSecurityCookieBytes[5] += 1;
                }

                securityCookieBytes = new byte[8];

                partialSecurityCookieBytes.CopyTo(securityCookieBytes, 0);
            }

            // Write the security cookie into the remote process

            _processManager.Memory.Write(DllBaseAddress + _peImage.SecurityCookie.Offset, securityCookieBytes);
        }

        private void LoadDependencies()
        {
            var apiSetMappings = new Lazy<Dictionary<string, string>>(_processManager.ReadApiSetMappings);

            foreach (var importDescriptor in _peImage.ImportDescriptors)
            {
                // Resolve the name of the dependency if it is an API set

                if (importDescriptor.Name.StartsWith("api-ms"))
                {
                    importDescriptor.Name = apiSetMappings.Value[importDescriptor.Name];
                }

                // Write the name of the dependency into the remote process

                var dependencyNameBytes = Encoding.Unicode.GetBytes(importDescriptor.Name);

                var dependencyNameBuffer = _processManager.Memory.Allocate(dependencyNameBytes.Length, ProtectionType.ReadWrite);

                _processManager.Memory.Write(dependencyNameBuffer, dependencyNameBytes);

                // Load the dependency into the remote process, increasing its reference count if it is already loaded

                if (_processManager.CallFunction<IntPtr>(CallingConvention.StdCall, _processManager.GetFunctionAddress("kernel32.dll", "LoadLibraryW"), dependencyNameBuffer.ToInt64()) == IntPtr.Zero)
                {
                    throw new Win32Exception("Failed to call LoadLibraryW in the remote process");
                }

                _processManager.Memory.Free(dependencyNameBuffer);
            }

            _processManager.Refresh();
        }

        private void MapHeaders()
        {
            // Write the PE headers into the remote process

            _processManager.Memory.Write(DllBaseAddress, _dllBytes.Slice(0, _peImage.Headers.PEHeader.SizeOfHeaders));

            _processManager.Memory.Protect(DllBaseAddress, _peImage.Headers.PEHeader.SizeOfHeaders, ProtectionType.ReadOnly);
        }

        private void MapSections()
        {
            static ProtectionType CalculateSectionProtection(SectionCharacteristics sectionCharacteristics)
            {
                if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemExecute))
                {
                    if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                    {
                        return ProtectionType.ExecuteReadWrite;
                    }

                    return sectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ExecuteRead : ProtectionType.Execute;
                }

                if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                {
                    return ProtectionType.ReadWrite;
                }

                return sectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ReadOnly : ProtectionType.NoAccess;
            }

            foreach (var section in _peImage.Headers.SectionHeaders.Where(section => section.SizeOfRawData != 0 && !section.SectionCharacteristics.HasFlag(SectionCharacteristics.MemDiscardable)))
            {
                // Write the section into the remote process

                var sectionAddress = DllBaseAddress + section.VirtualAddress;

                _processManager.Memory.Write(sectionAddress, _dllBytes.Slice(section.PointerToRawData, section.SizeOfRawData));

                _processManager.Memory.Protect(sectionAddress, section.SizeOfRawData, CalculateSectionProtection(section.SectionCharacteristics));
            }
        }

        private void RelocateImage()
        {
            if (_peImage.Relocations.Count == 0)
            {
                return;
            }

            // Calculate the delta from the preferred base address

            var delta = DllBaseAddress.ToInt64() - (long) _peImage.Headers.PEHeader.ImageBase;

            foreach (var relocation in _peImage.Relocations)
            {
                switch (relocation.Type)
                {
                    case RelocationType.HighLow:
                    {
                        // Perform the relocation

                        MemoryMarshal.Write(_dllBytes.Slice(relocation.Offset).Span, ref Unsafe.AsRef(MemoryMarshal.Read<int>(_dllBytes.Slice(relocation.Offset).Span) + (int) delta));

                        break;
                    }

                    case RelocationType.Dir64:
                    {
                        // Perform the relocation

                        MemoryMarshal.Write(_dllBytes.Slice(relocation.Offset).Span, ref Unsafe.AsRef(MemoryMarshal.Read<long>(_dllBytes.Slice(relocation.Offset).Span) + delta));

                        break;
                    }
                }
            }
        }

        private void ValidateArchitecture()
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                throw new PlatformNotSupportedException("Native x86 systems are not supported");
            }

            if (!Environment.Is64BitProcess && !_processManager.IsWow64)
            {
                throw new NotSupportedException("x64 mapping is not supported from an x86 build");
            }

            if (_processManager.IsWow64 != (_peImage.Headers.PEHeader.Magic == PEMagic.PE32))
            {
                throw new ApplicationException("The architecture of the DLL must match that of the process");
            }
        }
    }
}