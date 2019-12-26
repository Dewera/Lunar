using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Lunar.FunctionCall;
using Lunar.FunctionCall.Structures;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Lunar.Native.Structures;
using Lunar.RemoteProcess.Structures;
using Microsoft.Win32.SafeHandles;

namespace Lunar.RemoteProcess
{
    internal sealed class ProcessManager
    {
        internal bool IsWow64 { get; }

        internal Memory Memory { get; }

        internal List<Module> Modules { get; }

        private readonly PebData _pebData;

        private readonly SafeProcessHandle _processHandle;

        internal ProcessManager(Process process)
        {
            _processHandle = process.SafeHandle;

            IsWow64 = IsProcessWow64();

            Memory = new Memory(process.SafeHandle);

            _pebData = ReadPebData();

            Modules = GetProcessModules();
        }

        internal TStructure CallFunction<TStructure>(CallingConvention callingConvention, IntPtr functionAddress, params long[] parameters) where TStructure : unmanaged
        {
            var returnBuffer = Memory.Allocate(Unsafe.SizeOf<TStructure>(), ProtectionType.ReadWrite);

            // Write the shellcode used to perform the function call into a buffer in the remote process

            var shellcode = Assembler.AssembleCallDescriptor(new CallDescriptor(functionAddress, callingConvention, IsWow64, parameters, returnBuffer));

            var shellcodeBuffer = Memory.Allocate(shellcode.Length, ProtectionType.ExecuteReadWrite);

            Memory.Write(shellcodeBuffer, shellcode);

            // Create a thread in the remote process to execute the shellcode

            var ntStatus = Ntdll.RtlCreateUserThread(_processHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, shellcodeBuffer, IntPtr.Zero, out var threadHandle, IntPtr.Zero);

            if (ntStatus != NtStatus.Success)
            {
                throw new Win32Exception($"Failed to call RtlCreateUserThread with error code {Ntdll.RtlNtStatusToDosError(ntStatus)}");
            }

            if (Kernel32.WaitForSingleObject(threadHandle, int.MaxValue) == -1)
            {
                throw new Win32Exception($"Failed to call WaitForSingleObject with error code {Marshal.GetLastWin32Error()}");
            }

            threadHandle.Dispose();

            Memory.Free(shellcodeBuffer);

            try
            {
                return Memory.Read<TStructure>(returnBuffer);
            }

            finally
            {
                Memory.Free(returnBuffer);
            }
        }

        internal IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            var functionModule = Modules.First(module => module.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            // Calculate the address of the function

            var function = functionModule.PeImage.Value.ExportedFunctions.First(exportedFunction => exportedFunction.Name.Equals(functionName));

            var functionAddress = functionModule.BaseAddress + function.Offset;

            // Determine if the function is forwarded to another function

            var exportDirectoryStartAddress = functionModule.BaseAddress + functionModule.PeImage.Value.Headers.PEHeader.ExportTableDirectory.RelativeVirtualAddress;

            var exportDirectoryEndAddress = exportDirectoryStartAddress + functionModule.PeImage.Value.Headers.PEHeader.ExportTableDirectory.Size;

            if (functionAddress.ToInt64() < exportDirectoryStartAddress.ToInt64() || functionAddress.ToInt64() > exportDirectoryEndAddress.ToInt64())
            {
                return functionAddress;
            }

            // Read the forwarded function

            var forwardedFunctionBytes = new List<byte>();

            while (true)
            {
                var currentByte = Memory.Read<byte>(functionAddress);

                if (currentByte == byte.MinValue)
                {
                    break;
                }

                forwardedFunctionBytes.Add(currentByte);

                functionAddress += 1;
            }

            var forwardedFunction = Encoding.UTF8.GetString(forwardedFunctionBytes.ToArray()).Split(".");

            return GetFunctionAddress(forwardedFunction[0] + ".dll", forwardedFunction[1]);
        }

        internal Dictionary<string, string> ReadApiSetMappings()
        {
            var apiSetMappings = new Dictionary<string, string>();

            // Read the API set namespace

            var apiSetNamespace = Memory.Read<ApiSetNamespace>(_pebData.ApiSetMap);

            for (var namespaceEntryIndex = 0; namespaceEntryIndex < apiSetNamespace.Count; namespaceEntryIndex ++)
            {
                // Read the name of the namespace entry

                var namespaceEntry = Memory.Read<ApiSetNamespaceEntry>(_pebData.ApiSetMap + apiSetNamespace.EntryOffset + Unsafe.SizeOf<ApiSetNamespaceEntry>() * namespaceEntryIndex);

                var namespaceEntryNameBytes = Memory.Read(_pebData.ApiSetMap + namespaceEntry.NameOffset, namespaceEntry.NameLength);

                var namespaceEntryName = Encoding.Unicode.GetString(namespaceEntryNameBytes.Span) + ".dll";

                // Read the name of the value entry that the namespace entry maps to

                var valueEntry = Memory.Read<ApiSetValueEntry>(_pebData.ApiSetMap + namespaceEntry.ValueOffset);

                if (valueEntry.ValueCount == 0)
                {
                    apiSetMappings.Add(namespaceEntryName, "");
                }

                else
                {
                    var valueEntryNameBytes = Memory.Read(_pebData.ApiSetMap + valueEntry.ValueOffset, valueEntry.ValueCount);

                    var valueEntryName = Encoding.Unicode.GetString(valueEntryNameBytes.Span);

                    apiSetMappings.Add(namespaceEntryName, valueEntryName);
                }
            }

            return apiSetMappings;
        }

        internal void Refresh()
        {
            Modules.Clear();

            Modules.AddRange(GetProcessModules());
        }

        private List<Module> GetProcessModules()
        {
            var modules = new List<Module>();

            if (IsWow64)
            {
                var filePathRegex = new Regex("System32", RegexOptions.IgnoreCase);

                // Read the loader data of the PEB

                var pebLoaderData = Memory.Read<PebLdrData32>(_pebData.Loader);

                // Read the entries of the InMemoryOrder doubly linked list

                var currentEntryAddress = pebLoaderData.InMemoryOrderModuleList.Flink;

                var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry32>("InMemoryOrderLinks");

                while (true)
                {
                    var entry = Memory.Read<LdrDataTableEntry32>(new IntPtr(currentEntryAddress) - inMemoryOrderLinksOffset.ToInt32());

                    // Read the file path of the entry

                    var entryFilePathBytes = Memory.Read(new IntPtr(entry.FullDllName.Buffer), entry.FullDllName.Length);

                    var entryFilePath = filePathRegex.Replace(Encoding.Unicode.GetString(entryFilePathBytes.Span), "SysWOW64");

                    // Read the name of the entry

                    var entryNameBytes = Memory.Read(new IntPtr(entry.BaseDllName.Buffer), entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes.Span);

                    modules.Add(new Module(new IntPtr(entry.DllBase), entryFilePath, entryName));

                    if (currentEntryAddress == pebLoaderData.InMemoryOrderModuleList.Blink)
                    {
                        break;
                    }

                    // Determine the address of the next entry

                    currentEntryAddress = entry.InMemoryOrderLinks.Flink;
                }
            }

            else
            {
                // Read the loader data of the PEB

                var pebLoaderData = Memory.Read<PebLdrData64>(_pebData.Loader);

                // Read the entries of the InMemoryOrder doubly linked list

                var currentEntryAddress = pebLoaderData.InMemoryOrderModuleList.Flink;

                var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry64>("InMemoryOrderLinks");

                while (true)
                {
                    var entry = Memory.Read<LdrDataTableEntry64>(new IntPtr(currentEntryAddress) - inMemoryOrderLinksOffset.ToInt32());

                    // Read the file path of the entry

                    var entryFilePathBytes = Memory.Read(new IntPtr(entry.FullDllName.Buffer), entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes.Span);

                    // Read the name of the entry

                    var entryNameBytes = Memory.Read(new IntPtr(entry.BaseDllName.Buffer), entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes.Span);

                    modules.Add(new Module(new IntPtr(entry.DllBase), entryFilePath, entryName));

                    if (currentEntryAddress == pebLoaderData.InMemoryOrderModuleList.Blink)
                    {
                        break;
                    }

                    // Determine the address of the next entry

                    currentEntryAddress = entry.InMemoryOrderLinks.Flink;
                }
            }

            return modules;
        }

        private bool IsProcessWow64()
        {
            if (!Kernel32.IsWow64Process(_processHandle, out var isWow64Process))
            {
                throw new Win32Exception($"Failed to call IsWow64Process with error code {Marshal.GetLastWin32Error()}");
            }

            return isWow64Process;
        }

        private PebData ReadPebData()
        {
            if (IsWow64)
            {
                // Query the process for the address of its WOW64 PEB

                var wow64PebAddressBytes = new byte[sizeof(long)];

                var ntStatus = Ntdll.NtQueryInformationProcess(_processHandle, ProcessInformationClass.Wow64Information, ref wow64PebAddressBytes[0], wow64PebAddressBytes.Length, out _);

                if (ntStatus != NtStatus.Success)
                {
                    throw new Win32Exception($"Failed to call NtQueryInformationProcess with error code {Ntdll.RtlNtStatusToDosError(ntStatus)}");
                }

                var wow64PebAddress = MemoryMarshal.Read<IntPtr>(wow64PebAddressBytes);

                // Read the WOW64 PEB data

                var wow64Peb = Memory.Read<Peb32>(wow64PebAddress);

                return new PebData(new IntPtr(wow64Peb.ApiSetMap), new IntPtr(wow64Peb.Ldr));
            }

            else
            {
                // Query the process for the address of its PEB

                var processBasicInformationBytes = new byte[Unsafe.SizeOf<ProcessBasicInformation>()];

                var ntStatus = Ntdll.NtQueryInformationProcess(_processHandle, ProcessInformationClass.BasicInformation, ref processBasicInformationBytes[0], processBasicInformationBytes.Length, out _);

                if (ntStatus != NtStatus.Success)
                {
                    throw new Win32Exception($"Failed to call NtQueryInformationProcess with error code {Ntdll.RtlNtStatusToDosError(ntStatus)}");
                }

                // Read the PEB data

                var processBasicInformation = MemoryMarshal.Read<ProcessBasicInformation>(processBasicInformationBytes);

                var peb = Memory.Read<Peb64>(processBasicInformation.PebBaseAddress);

                return new PebData(new IntPtr(peb.ApiSetMap), new IntPtr(peb.Ldr));
            }
        }
    }
}