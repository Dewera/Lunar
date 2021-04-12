using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Extensions;
using Lunar.FileResolution;
using Lunar.Native;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Lunar.PortableExecutable;
using Lunar.Remote.Structures;
using Lunar.Shellcode;
using Lunar.Shellcode.Structures;

namespace Lunar.Remote
{
    internal sealed class ProcessContext
    {
        internal Memory Memory { get; }

        internal Process Process { get; }

        private readonly ApiSetMap _apiSetMap;

        private readonly IDictionary<string, Module> _moduleCache;

        private readonly SymbolHandler _symbolHandler;

        internal ProcessContext(Process process)
        {
            _apiSetMap = new ApiSetMap();

            _moduleCache = new ConcurrentDictionary<string, Module>(StringComparer.OrdinalIgnoreCase);

            _symbolHandler = new SymbolHandler(process);

            Memory = new Memory(process.SafeHandle);

            Process = process;
        }

        internal void CallRoutine(IntPtr routineAddress, params dynamic[] arguments)
        {
            // Assemble the shellcode used to call the routine

            Span<byte> shellcodeBytes;

            if (Process.GetArchitecture() == Architecture.X86)
            {
                var callDescriptor = new CallDescriptor<int>(routineAddress, Array.ConvertAll(arguments, argument => (int) argument), IntPtr.Zero);

                shellcodeBytes = ShellcodeAssembler.AssembleCall32(callDescriptor);
            }

            else
            {
                var callDescriptor = new CallDescriptor<long>(routineAddress, Array.ConvertAll(arguments, argument => (long) argument), IntPtr.Zero);

                shellcodeBytes = ShellcodeAssembler.AssembleCall64(callDescriptor);
            }

            // Execute the shellcode

            ExecuteShellcode(shellcodeBytes);
        }

        internal T CallRoutine<T>(IntPtr routineAddress, params dynamic[] arguments) where T : unmanaged
        {
            var returnAddress = Memory.AllocateBuffer(Unsafe.SizeOf<T>(), ProtectionType.ReadWrite);

            try
            {
                // Assemble the shellcode used to call the routine

                Span<byte> shellcodeBytes;

                if (Process.GetArchitecture() == Architecture.X86)
                {
                    var callDescriptor = new CallDescriptor<int>(routineAddress, Array.ConvertAll(arguments, argument => (int) argument), returnAddress);

                    shellcodeBytes = ShellcodeAssembler.AssembleCall32(callDescriptor);
                }

                else
                {
                    var callDescriptor = new CallDescriptor<long>(routineAddress, Array.ConvertAll(arguments, argument => (long) argument), returnAddress);

                    shellcodeBytes = ShellcodeAssembler.AssembleCall64(callDescriptor);
                }

                // Execute the shellcode

                ExecuteShellcode(shellcodeBytes);

                return Memory.ReadStructure<T>(returnAddress);
            }

            finally
            {
                Memory.FreeBuffer(returnAddress);
            }
        }

        internal void ClearModuleCache()
        {
            _moduleCache.Clear();
        }

        internal IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            var containingModule = GetModule(moduleName);

            var function = containingModule.PeImage.ExportDirectory.GetExportedFunction(functionName);

            if (function is null)
            {
                throw new ApplicationException($"Failed to find the function {functionName} in the module {moduleName.ToLower()}");
            }

            return function.ForwarderString is null ? containingModule.Address + function.RelativeAddress : ResolveForwardedFunction(function.ForwarderString);
        }

        internal IntPtr GetFunctionAddress(string moduleName, int functionOrdinal)
        {
            var containingModule = GetModule(moduleName);

            var function = containingModule.PeImage.ExportDirectory.GetExportedFunction(functionOrdinal);

            if (function is null)
            {
                throw new ApplicationException($"Failed to find the function #{functionOrdinal} in the module {moduleName.ToLower()}");
            }

            return function.ForwarderString is null ? containingModule.Address + function.RelativeAddress : ResolveForwardedFunction(function.ForwarderString);
        }

        internal IntPtr GetModuleAddress(string moduleName)
        {
            return GetModule(moduleName).Address;
        }

        internal IntPtr GetNtdllSymbolAddress(string symbolName)
        {
            return GetModule("ntdll.dll").Address + _symbolHandler.GetSymbol(symbolName).RelativeAddress;
        }

        internal void NotifyModuleLoad(IntPtr moduleAddress, string moduleFilePath)
        {
            _moduleCache.TryAdd(Path.GetFileName(moduleFilePath), new Module(moduleAddress, new PeImage(File.ReadAllBytes(moduleFilePath))));
        }

        internal string ResolveModuleName(string moduleName)
        {
            if (moduleName.StartsWith("api-ms") || moduleName.StartsWith("ext-ms"))
            {
                return _apiSetMap.ResolveApiSet(moduleName) ?? moduleName;
            }

            return moduleName;
        }

        private void ExecuteShellcode(Span<byte> shellcodeBytes)
        {
            // Write the shellcode into the process

            var shellcodeAddress = Memory.AllocateBuffer(shellcodeBytes.Length, ProtectionType.ExecuteRead);

            try
            {
                Memory.WriteSpan(shellcodeAddress, shellcodeBytes);

                // Create a thread to execute the shellcode

                var status = Ntdll.RtlCreateUserThread(Process.SafeHandle, IntPtr.Zero, false, 0, 0, 0, shellcodeAddress, IntPtr.Zero, out var threadHandle, IntPtr.Zero);

                if (status != NtStatus.Success)
                {
                    throw new Win32Exception(Ntdll.RtlNtStatusToDosError(status));
                }

                using (threadHandle)
                {
                    if (Kernel32.WaitForSingleObject(threadHandle, int.MaxValue) == -1)
                    {
                        throw new Win32Exception();
                    }
                }
            }

            finally
            {
                Memory.FreeBuffer(shellcodeAddress);
            }
        }

        private Module GetModule(string moduleName)
        {
            moduleName = ResolveModuleName(moduleName);

            if (_moduleCache.TryGetValue(moduleName, out var module))
            {
                return module;
            }

            // Query the process for an array of its module addresses

            const int arbitraryModuleAmount = 512;

            Span<IntPtr> moduleAddressArray = stackalloc IntPtr[arbitraryModuleAmount];

            var moduleType = Process.GetArchitecture() == Architecture.X86 ? ModuleType.X86 : ModuleType.X64;

            if (!Kernel32.K32EnumProcessModulesEx(Process.SafeHandle, out moduleAddressArray[0], IntPtr.Size * arbitraryModuleAmount, out var sizeNeeded, moduleType))
            {
                throw new Win32Exception();
            }

            Span<byte> moduleFilePathBytes = stackalloc byte[Encoding.Unicode.GetMaxByteCount(Constants.MaxPath)];

            foreach (var moduleAddress in moduleAddressArray[..(sizeNeeded / IntPtr.Size)])
            {
                moduleFilePathBytes.Clear();

                // Retrieve the file path of the module

                if (!Kernel32.K32GetModuleFileNameEx(Process.SafeHandle, moduleAddress, out moduleFilePathBytes[0], Encoding.Unicode.GetCharCount(moduleFilePathBytes)))
                {
                    throw new Win32Exception();
                }

                var moduleFilePath = Encoding.Unicode.GetString(moduleFilePathBytes).TrimEnd('\0');

                if (Environment.Is64BitOperatingSystem && Process.GetArchitecture() == Architecture.X86)
                {
                    // Redirect the file path to the WOW64 directory

                    moduleFilePath = moduleFilePath.Replace("System32", "SysWOW64", StringComparison.OrdinalIgnoreCase);
                }

                if (!moduleName.Equals(Path.GetFileName(moduleFilePath), StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                module = new Module(moduleAddress, new PeImage(File.ReadAllBytes(moduleFilePath)));

                _moduleCache.TryAdd(Path.GetFileName(moduleFilePath), module);

                return module;
            }

            throw new ApplicationException($"Failed to find the module {moduleName.ToLower()} in the process");
        }

        private IntPtr ResolveForwardedFunction(string forwarderString)
        {
            while (true)
            {
                var forwardedData = forwarderString.Split(".");

                var forwardedModule = GetModule($"{forwardedData[0]}.dll");

                var forwardedFunction = forwardedData[1].StartsWith("#") ? forwardedModule.PeImage.ExportDirectory.GetExportedFunction(int.Parse(forwardedData[1].Replace("#", string.Empty))) : forwardedModule.PeImage.ExportDirectory.GetExportedFunction(forwardedData[1]);

                if (forwardedFunction is null)
                {
                    throw new ApplicationException($"Failed to find the function {forwardedData[1]} in the module {forwardedData[0].ToLower()}.dll");
                }

                if (forwardedFunction.ForwarderString is null || forwardedFunction.ForwarderString.Equals(forwarderString, StringComparison.OrdinalIgnoreCase))
                {
                    return forwardedModule.Address + forwardedFunction.RelativeAddress;
                }

                forwarderString = forwardedFunction.ForwarderString;
            }
        }
    }
}