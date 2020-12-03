using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Assembly;
using Lunar.Assembly.Structures;
using Lunar.Extensions;
using Lunar.FileResolution;
using Lunar.PortableExecutable;
using Lunar.Remote.Structures;

namespace Lunar.Remote
{
    internal sealed class ProcessContext
    {
        internal Process Process { get; }

        private readonly ApiSetMap _apiSetMap;

        private readonly Loader _loader;

        private readonly IDictionary<string, Module> _moduleCache;

        private readonly SymbolHandler _symbolHandler;

        internal ProcessContext(Process process)
        {
            _apiSetMap = new ApiSetMap();

            _loader = new Loader(process);

            _moduleCache = new Dictionary<string, Module>(StringComparer.OrdinalIgnoreCase);

            _symbolHandler = new SymbolHandler(Path.Combine(process.GetSystemDirectoryPath(), "ntdll.dll"));

            Process = process;
        }

        internal void CallRoutine(IntPtr routineAddress, params dynamic[] arguments)
        {
            // Create the shellcode used to call the routine

            Span<byte> shellcodeBytes;

            if (Process.GetArchitecture() == Architecture.X86)
            {
                var callDescriptor = new CallDescriptor32(routineAddress, Array.ConvertAll(arguments, argument => (int) argument), IntPtr.Zero);

                shellcodeBytes = Assembler.AssembleCall32(callDescriptor);
            }

            else
            {
                var routineDescriptor = new CallDescriptor64(routineAddress, Array.ConvertAll(arguments, argument => (long) argument), IntPtr.Zero);

                shellcodeBytes = Assembler.AssembleCall64(routineDescriptor);
            }

            // Write the shellcode into the process

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

                shellcodeBytes = Assembler.AssembleCall32(callDescriptor);
            }

            else
            {
                var routineDescriptor = new CallDescriptor64(routineAddress, Array.ConvertAll(arguments, argument => (long) argument), returnAddress);

                shellcodeBytes = Assembler.AssembleCall64(routineDescriptor);
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
                throw new ApplicationException($"Failed to find the function {functionName} in the module {moduleName}");
            }

            return function.ForwarderString is null ? containingModule.Address + function.RelativeAddress : ResolveForwardedFunction(function.ForwarderString);
        }

        internal IntPtr GetFunctionAddress(string moduleName, int functionOrdinal)
        {
            var containingModule = GetModule(moduleName);

            var function = containingModule.PeImage.ExportDirectory.GetExportedFunction(functionOrdinal);

            if (function is null)
            {
                throw new ApplicationException($"Failed to find the function #{functionOrdinal} in the module {moduleName}");
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
            var moduleName = Path.GetFileName(moduleFilePath);

            _moduleCache.TryAdd(moduleName, new Module(moduleAddress, Path.GetFileName(moduleFilePath), new PeImage(File.ReadAllBytes(moduleFilePath))));
        }

        internal string ResolveModuleName(string moduleName)
        {
            if (moduleName.StartsWith("api-ms") || moduleName.StartsWith("ext-ms"))
            {
                return _apiSetMap.ResolveApiSet(moduleName) ?? moduleName;
            }

            return moduleName;
        }

        private Module GetModule(string moduleName)
        {
            moduleName = ResolveModuleName(moduleName);

            if (_moduleCache.TryGetValue(moduleName, out var module))
            {
                return module;
            }

            module = _loader.GetModule(moduleName);

            if (module is null)
            {
                throw new ApplicationException($"Failed to find the module {moduleName} in the process");
            }

            _moduleCache.Add(moduleName, module);

            return module;
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
                    throw new ApplicationException($"Failed to resolve the forwarded function {forwarderString}");
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