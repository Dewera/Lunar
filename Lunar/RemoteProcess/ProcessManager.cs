using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Assembler;
using Lunar.Assembler.Structures;
using Lunar.Extensions;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Lunar.RemoteProcess.Structures;

namespace Lunar.RemoteProcess
{
    internal sealed class ProcessManager
    {
        internal Process Process { get; }

        private readonly List<Module> _modules;

        private readonly PebAccessor _pebAccessor;

        internal ProcessManager(Process process)
        {
            _modules = new List<Module>();

            _pebAccessor = new PebAccessor(process);

            Process = process;

            Refresh();
        }

        internal void CallRoutine(IntPtr routineAddress, params dynamic[] parameters)
        {
            var routineDescriptor = new RoutineDescriptor(routineAddress, parameters, IntPtr.Zero);

            CallRoutine(routineDescriptor);
        }

        internal T CallRoutine<T>(IntPtr routineAddress, params dynamic[] parameters) where T : unmanaged
        {
            var returnBufferAddress = Process.AllocateBuffer(Unsafe.SizeOf<T>());

            var routineDescriptor = new RoutineDescriptor(routineAddress, parameters, returnBufferAddress);

            try
            {
                CallRoutine(routineDescriptor);

                return Process.ReadStructure<T>(returnBufferAddress);
            }

            finally
            {
                Process.FreeBuffer(returnBufferAddress);
            }
        }

        internal IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            var containingModule = _modules.First(module => module.Name.Equals(ResolveModuleName(moduleName), StringComparison.OrdinalIgnoreCase));

            var exportedFunction = containingModule.ExportedFunctions.Value.First(function => function.Name.Equals(functionName));

            // Check if the exported function is forwarded

            if (exportedFunction.ForwarderString is null)
            {
                return containingModule.Address + exportedFunction.Rva;
            }

            // Resolve the forwarded function

            var forwardedData = exportedFunction.ForwarderString.Split(".");

            var forwardedModuleName = $"{forwardedData[0]}.dll";

            var forwardedFunctionName = forwardedData[1];

            // Handle circular forwarding to avoid infinite recursion

            if (moduleName.Equals(forwardedModuleName, StringComparison.OrdinalIgnoreCase) && functionName.Equals(forwardedFunctionName, StringComparison.OrdinalIgnoreCase))
            {
                return containingModule.Address + exportedFunction.Rva;
            }

            return GetFunctionAddress(forwardedModuleName, forwardedFunctionName);
        }

        internal IntPtr GetFunctionAddress(string moduleName, int functionOrdinal)
        {
            var containingModule = _modules.First(module => module.Name.Equals(ResolveModuleName(moduleName), StringComparison.OrdinalIgnoreCase));

            var exportedFunction = containingModule.ExportedFunctions.Value.First(function => function.Ordinal == functionOrdinal);

            return GetFunctionAddress(moduleName, exportedFunction.Name);
        }

        internal IntPtr GetModuleAddress(string moduleName)
        {
            return _modules.First(module => module.Name.Equals(ResolveModuleName(moduleName), StringComparison.OrdinalIgnoreCase)).Address;
        }

        internal void Refresh()
        {
            _modules.Clear();

            _modules.AddRange(_pebAccessor.ReadModules());
        }

        internal string ResolveModuleName(string moduleName)
        {
            if (moduleName.StartsWith("api-ms"))
            {
                return _pebAccessor.ResolveApiSetName(moduleName);
            }

            return moduleName;
        }

        private void CallRoutine(RoutineDescriptor routineDescriptor)
        {
            // Write the shellcode used to perform the function call into a buffer

            Span<byte> shellcodeBuffer;

            if (Process.GetArchitecture() == Architecture.X86)
            {
                shellcodeBuffer = RoutineAssembler.AssembleRoutine32(routineDescriptor);
            }

            else
            {
                shellcodeBuffer = RoutineAssembler.AssembleRoutine64(routineDescriptor);
            }

            var shellcodeBufferAddress = Process.AllocateBuffer(shellcodeBuffer.Length, true);

            try
            {
                Process.WriteBuffer(shellcodeBufferAddress, shellcodeBuffer);

                // Create a thread to execute the shellcode

                var ntStatus = Ntdll.NtCreateThreadEx(out var threadHandle, AccessMask.SpecificRightsAll | AccessMask.StandardRightsAll, IntPtr.Zero, Process.SafeHandle, shellcodeBufferAddress, IntPtr.Zero, ThreadCreationFlags.HideFromDebugger | ThreadCreationFlags.SkipThreadAttach, IntPtr.Zero, 0, 0, IntPtr.Zero);

                using (threadHandle)
                {
                    if (ntStatus != NtStatus.Success)
                    {
                        throw new Win32Exception(Ntdll.RtlNtStatusToDosError(ntStatus));
                    }

                    if (Kernel32.WaitForSingleObject(threadHandle, int.MaxValue) == -1)
                    {
                        throw new Win32Exception();
                    }
                }
            }

            finally
            {
                Process.FreeBuffer(shellcodeBufferAddress);
            }
        }
    }
}