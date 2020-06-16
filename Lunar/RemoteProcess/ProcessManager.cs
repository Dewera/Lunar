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

        internal void CallRoutine(IntPtr functionAddress, params dynamic[] parameters)
        {
            var routineDescriptor = new RoutineDescriptor(functionAddress, parameters, IntPtr.Zero);

            CallRoutine(routineDescriptor);
        }

        internal TStructure CallRoutine<TStructure>(IntPtr functionAddress, params dynamic[] parameters) where TStructure : unmanaged
        {
            var returnBuffer = Process.AllocateBuffer(Unsafe.SizeOf<TStructure>());

            var routineDescriptor = new RoutineDescriptor(functionAddress, parameters, returnBuffer);

            try
            {
                CallRoutine(routineDescriptor);

                return Process.ReadStructure<TStructure>(returnBuffer);
            }

            finally
            {
                Process.FreeBuffer(returnBuffer);
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
            return moduleName.StartsWith("api-ms") ? _pebAccessor.ResolveApiSetName(moduleName) : moduleName;
        }

        private void CallRoutine(RoutineDescriptor routineDescriptor)
        {
            // Write the shellcode used to perform the function call into a buffer

            var shellcodeBlock = Process.GetArchitecture() == Architecture.X86 ? RoutineAssembler.AssembleRoutine32(routineDescriptor) : RoutineAssembler.AssembleRoutine64(routineDescriptor);

            var shellcodeBuffer = Process.AllocateBuffer(shellcodeBlock.Length, true);

            try
            {
                Process.WriteArray(shellcodeBuffer, shellcodeBlock);

                // Create a thread to execute the shellcode

                const AccessMask accessMask = AccessMask.SpecificRightsAll | AccessMask.StandardRightsAll;

                const ThreadCreationFlags creationFlags = ThreadCreationFlags.HideFromDebugger | ThreadCreationFlags.SkipThreadAttach;

                var ntStatus = Ntdll.NtCreateThreadEx(out var threadHandle, accessMask, IntPtr.Zero, Process.SafeHandle, shellcodeBuffer, IntPtr.Zero, creationFlags, IntPtr.Zero, 0, 0, IntPtr.Zero);

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
                Process.FreeBuffer(shellcodeBuffer);
            }
        }
    }
}