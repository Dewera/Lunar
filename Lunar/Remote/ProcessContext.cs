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
using Lunar.Native.Enums;
using Lunar.Native.PInvoke;
using Lunar.Native.Structs;
using Lunar.PortableExecutable;
using Lunar.PortableExecutable.Records;
using Lunar.Remote.Records;
using Lunar.Shellcode;
using Lunar.Shellcode.Records;
using Lunar.Utilities;

namespace Lunar.Remote
{
    internal sealed class ProcessContext
    {
        internal Architecture Architecture { get; }
        internal Process Process { get; }

        private readonly ApiSetMap _apiSetMap;
        private readonly IDictionary<string, Module> _moduleCache;
        private readonly SymbolHandler _symbolHandler;

        internal ProcessContext(Process process)
        {
            _apiSetMap = new ApiSetMap();
            _moduleCache = new ConcurrentDictionary<string, Module>(StringComparer.OrdinalIgnoreCase);
            _symbolHandler = new SymbolHandler(process.GetArchitecture());

            Architecture = process.GetArchitecture();
            Process = process;
        }

        internal void CallRoutine(IntPtr routineAddress, params dynamic[] arguments)
        {
            // Assemble the shellcode used to call the routine

            Span<byte> shellcodeBytes;

            if (Architecture == Architecture.X86)
            {
                var callDescriptor = new CallDescriptor<int>(routineAddress, Array.ConvertAll(arguments, argument => (int) argument), IntPtr.Zero);
                shellcodeBytes = Assembler.AssembleCall32(callDescriptor);
            }

            else
            {
                var callDescriptor = new CallDescriptor<long>(routineAddress, Array.ConvertAll(arguments, argument => (long) argument), IntPtr.Zero);
                shellcodeBytes = Assembler.AssembleCall64(callDescriptor);
            }

            ExecuteShellcode(shellcodeBytes);
        }

        internal T CallRoutine<T>(IntPtr routineAddress, params dynamic[] arguments) where T : unmanaged
        {
            var returnSize = typeof(T) == typeof(IntPtr) ? Architecture == Architecture.X86 ? sizeof(int) : sizeof(long) : Unsafe.SizeOf<T>();
            var returnAddress = Process.AllocateBuffer(returnSize, ProtectionType.ReadWrite);

            try
            {
                // Assemble the shellcode used to call the routine

                Span<byte> shellcodeBytes;

                if (Architecture == Architecture.X86)
                {
                    var callDescriptor = new CallDescriptor<int>(routineAddress, Array.ConvertAll(arguments, argument => (int) argument), returnAddress);
                    shellcodeBytes = Assembler.AssembleCall32(callDescriptor);
                }

                else
                {
                    var callDescriptor = new CallDescriptor<long>(routineAddress, Array.ConvertAll(arguments, argument => (long) argument), returnAddress);
                    shellcodeBytes = Assembler.AssembleCall64(callDescriptor);
                }

                ExecuteShellcode(shellcodeBytes);

                // Read the return value

                if (typeof(T) != typeof(IntPtr))
                {
                    return Process.ReadStruct<T>(returnAddress);
                }

                var pointer = Architecture == Architecture.X86 ? UnsafeHelpers.WrapPointer(Process.ReadStruct<int>(returnAddress)) : UnsafeHelpers.WrapPointer(Process.ReadStruct<long>(returnAddress));

                return Unsafe.As<IntPtr, T>(ref pointer);
            }

            finally
            {
                Executor.IgnoreExceptions(() => Process.FreeBuffer(returnAddress));
            }
        }

        internal void ClearModuleCache()
        {
            _moduleCache.Clear();
        }

        internal IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            var (moduleAddress, peImage) = GetModule(moduleName);
            var function = peImage.ExportDirectory.GetExportedFunction(functionName);

            if (function is null)
            {
                throw new ApplicationException($"Failed to find the function {functionName} in the module {moduleName.ToLower()}");
            }

            return function.ForwarderString is null ? moduleAddress + function.RelativeAddress : ResolveForwardedFunction(function.ForwarderString);
        }

        internal IntPtr GetFunctionAddress(string moduleName, int functionOrdinal)
        {
            var (moduleAddress, peImage) = GetModule(moduleName);
            var function = peImage.ExportDirectory.GetExportedFunction(functionOrdinal);

            if (function is null)
            {
                throw new ApplicationException($"Failed to find the function #{functionOrdinal} in the module {moduleName.ToLower()}");
            }

            return function.ForwarderString is null ? moduleAddress + function.RelativeAddress : ResolveForwardedFunction(function.ForwarderString);
        }

        internal IntPtr GetHeapAddress()
        {
            if (Architecture == Architecture.X86)
            {
                // Read the process WOW64 PEB

                var pebAddress = Process.QueryInformation<IntPtr>(ProcessInformationType.Wow64Information);
                var peb = Process.ReadStruct<Peb32>(pebAddress);

                return UnsafeHelpers.WrapPointer(peb.ProcessHeap);
            }

            else
            {
                // Read the process PEB

                var basicInformation = Process.QueryInformation<ProcessBasicInformation64>(ProcessInformationType.BasicInformation);
                var pebAddress = UnsafeHelpers.WrapPointer(basicInformation.PebBaseAddress);
                var peb = Process.ReadStruct<Peb64>(pebAddress);

                return UnsafeHelpers.WrapPointer(peb.ProcessHeap);
            }
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
                return _apiSetMap.ResolveApiSetName(moduleName) ?? moduleName;
            }

            return moduleName;
        }

        private void ExecuteShellcode(Span<byte> shellcodeBytes)
        {
            // Write the shellcode into the process

            var shellcodeAddress = Process.AllocateBuffer(shellcodeBytes.Length, ProtectionType.ExecuteRead);

            try
            {
                Process.WriteSpan(shellcodeAddress, shellcodeBytes);

                // Create a thread to execute the shellcode

                Process.CreateThread(shellcodeAddress);
            }

            finally
            {
                Executor.IgnoreExceptions(() => Process.FreeBuffer(shellcodeAddress));
            }
        }

        private Module GetModule(string moduleName)
        {
            moduleName = ResolveModuleName(moduleName);

            if (_moduleCache.TryGetValue(moduleName, out var module))
            {
                return module;
            }

            // Query the process for a list of its module addresses

            Span<byte> moduleAddressListBytes = stackalloc byte[IntPtr.Size];
            var moduleType = Architecture == Architecture.X86 ? ModuleType.X86 : ModuleType.X64;

            if (!Kernel32.K32EnumProcessModulesEx(Process.SafeHandle, out moduleAddressListBytes[0], moduleAddressListBytes.Length, out var sizeNeeded, moduleType))
            {
                throw new Win32Exception();
            }

            if (sizeNeeded > moduleAddressListBytes.Length)
            {
                // Reallocate the module address buffer

                moduleAddressListBytes = stackalloc byte[sizeNeeded];

                if (!Kernel32.K32EnumProcessModulesEx(Process.SafeHandle, out moduleAddressListBytes[0], moduleAddressListBytes.Length, out sizeNeeded, moduleType))
                {
                    throw new Win32Exception();
                }
            }

            // Search for the module

            Span<byte> moduleFilePathBytes = stackalloc byte[Encoding.Unicode.GetMaxByteCount(Constants.MaxPath)];

            foreach (var moduleAddress in MemoryMarshal.Cast<byte, IntPtr>(moduleAddressListBytes))
            {
                moduleFilePathBytes.Clear();

                // Retrieve the module file path

                if (!Kernel32.K32GetModuleFileNameEx(Process.SafeHandle, moduleAddress, out moduleFilePathBytes[0], Encoding.Unicode.GetCharCount(moduleFilePathBytes)))
                {
                    throw new Win32Exception();
                }

                var moduleFilePath = Encoding.Unicode.GetString(moduleFilePathBytes).TrimEnd('\0');

                if (Architecture == Architecture.X86)
                {
                    // Redirect the file path to the WOW64 directory

                    moduleFilePath = moduleFilePath.Replace("System32", "SysWOW64", StringComparison.OrdinalIgnoreCase);
                }

                if (!moduleName.Equals(Path.GetFileName(moduleFilePath), StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                _moduleCache.TryAdd(moduleName, new Module(moduleAddress, new PeImage(File.ReadAllBytes(moduleFilePath))));

                return _moduleCache[moduleName];
            }

            throw new ApplicationException($"Failed to find the module {moduleName.ToLower()} in the process");
        }

        private IntPtr ResolveForwardedFunction(string forwarderString)
        {
            while (true)
            {
                var forwardedData = forwarderString.Split(".");
                var (moduleAddress, peImage) = GetModule($"{forwardedData[0]}.dll");

                // Retrieve the forwarded function

                ExportedFunction? forwardedFunction;

                if (forwardedData[1].StartsWith("#"))
                {
                    var functionOrdinal = int.Parse(forwardedData[1].Replace("#", string.Empty));
                    forwardedFunction = peImage.ExportDirectory.GetExportedFunction(functionOrdinal);
                }

                else
                {
                    forwardedFunction = peImage.ExportDirectory.GetExportedFunction(forwardedData[1]);
                }

                if (forwardedFunction is null)
                {
                    throw new ApplicationException($"Failed to find the function {forwardedData[1]} in the module {forwardedData[0].ToLower()}.dll");
                }

                // Handle cyclical forwarding

                if (forwardedFunction.ForwarderString is null || forwardedFunction.ForwarderString.Equals(forwarderString, StringComparison.OrdinalIgnoreCase))
                {
                    return moduleAddress + forwardedFunction.RelativeAddress;
                }

                forwarderString = forwardedFunction.ForwarderString;
            }
        }
    }
}