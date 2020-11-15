using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Assembler;
using Lunar.Assembler.Structures;
using Lunar.Extensions;
using Lunar.Remote.Structures;

namespace Lunar.Remote
{
    internal sealed class ProcessContext
    {
        internal Process Process { get; }

        private readonly ApiSetMap _apiSetMap;

        private readonly Loader _loader;

        private readonly IDictionary<string, Module> _moduleCache;

        internal ProcessContext(Process process)
        {
            _apiSetMap = new ApiSetMap(process);

            _loader = new Loader(process);

            _moduleCache = new Dictionary<string, Module>(StringComparer.OrdinalIgnoreCase);

            Process = process;

            Refresh();
        }

        internal void CallRoutine(IntPtr routineAddress, params dynamic[] arguments)
        {
            // Create the shellcode used to call the routine

            Span<byte> shellcodeBytes;

            if (Process.GetArchitecture() == Architecture.X86)
            {
                var callDescriptor = new CallDescriptor32(routineAddress, Array.ConvertAll(arguments, argument => (int) argument), IntPtr.Zero);

                shellcodeBytes = CallAssembler.AssembleCall32(callDescriptor);
            }

            else
            {
                var routineDescriptor = new CallDescriptor64(routineAddress, Array.ConvertAll(arguments, argument => (long) argument), IntPtr.Zero);

                shellcodeBytes = CallAssembler.AssembleCall64(routineDescriptor);
            }

            // Write the shellcode bytes into the process

            var shellcodeBytesAddress = Process.AllocateMemory(shellcodeBytes.Length, true);

            try
            {
                Process.WriteArray(shellcodeBytesAddress, shellcodeBytes);

                // Create a thread to execute the shellcode

                Process.CreateThread(shellcodeBytesAddress);
            }

            finally
            {
                Process.FreeMemory(shellcodeBytesAddress);
            }
        }

        internal T CallRoutine<T>(IntPtr routineAddress, params dynamic[] arguments) where T : unmanaged
        {
            var returnAddress = Process.AllocateMemory(Unsafe.SizeOf<T>());

            // Create the shellcode used to call the routine

            Span<byte> shellcodeBytes;

            if (Process.GetArchitecture() == Architecture.X86)
            {
                var callDescriptor = new CallDescriptor32(routineAddress, Array.ConvertAll(arguments, argument => (int) argument), returnAddress);

                shellcodeBytes = CallAssembler.AssembleCall32(callDescriptor);
            }

            else
            {
                var routineDescriptor = new CallDescriptor64(routineAddress, Array.ConvertAll(arguments, argument => (long) argument), returnAddress);

                shellcodeBytes = CallAssembler.AssembleCall64(routineDescriptor);
            }

            try
            {
                // Write the shellcode bytes into the process

                var shellcodeBytesAddress = Process.AllocateMemory(shellcodeBytes.Length, true);

                try
                {
                    Process.WriteArray(shellcodeBytesAddress, shellcodeBytes);

                    // Create a thread to execute the shellcode

                    Process.CreateThread(shellcodeBytesAddress);
                }

                finally
                {
                    Process.FreeMemory(shellcodeBytesAddress);
                }

                return Process.ReadStructure<T>(returnAddress);
            }

            finally
            {
                Process.FreeMemory(returnAddress);
            }
        }

        internal IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            var containingModule = GetModule(moduleName);

            var function = containingModule?.PeImage.Value.ExportDirectory.GetExportedFunction(functionName);

            if (function is null)
            {
                return IntPtr.Zero;
            }

            return function.ForwarderString is null ? containingModule!.Address + function.RelativeAddress : ResolveForwardedFunction(function.ForwarderString);
        }

        internal IntPtr GetFunctionAddress(string moduleName, int functionOrdinal)
        {
            var containingModule = GetModule(moduleName);

            var function = containingModule?.PeImage.Value.ExportDirectory.GetExportedFunction(functionOrdinal);

            if (function is null)
            {
                return IntPtr.Zero;
            }

            return function.ForwarderString is null ? containingModule!.Address + function.RelativeAddress : ResolveForwardedFunction(function.ForwarderString);
        }

        internal IntPtr GetModuleAddress(string moduleName)
        {
            return GetModule(moduleName)?.Address ?? IntPtr.Zero;
        }

        internal void Refresh()
        {
            _moduleCache.Clear();

            foreach (var module in _loader.GetModules())
            {
                _moduleCache.Add(module.Name, module);
            }
        }

        internal string ResolveModuleName(string moduleName)
        {
            if (moduleName.StartsWith("api-ms") || moduleName.StartsWith("ext-ms"))
            {
                return _apiSetMap.ResolveApiSet(moduleName) ?? moduleName;
            }

            return moduleName;
        }

        private Module? GetModule(string moduleName)
        {
            moduleName = ResolveModuleName(moduleName);

            return _moduleCache.ContainsKey(moduleName) ? _moduleCache[moduleName] : null;
        }

        private IntPtr ResolveForwardedFunction(string forwarderString)
        {
            while (true)
            {
                var forwardedData = forwarderString.Split(".");

                var forwardedModule = GetModule($"{forwardedData[0]}.dll");

                if (forwardedModule is null)
                {
                    return IntPtr.Zero;
                }

                var forwardedFunction = forwardedData[1].StartsWith("#") ? forwardedModule.PeImage.Value.ExportDirectory.GetExportedFunction(int.Parse(forwardedData[1].Replace("#", string.Empty))) : forwardedModule.PeImage.Value.ExportDirectory.GetExportedFunction(forwardedData[1]);

                if (forwardedFunction is null)
                {
                    return IntPtr.Zero;
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