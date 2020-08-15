using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Extensions;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Lunar.Native.Structures;
using Lunar.RemoteProcess.Structures;
using Lunar.Shared;

namespace Lunar.RemoteProcess
{
    internal sealed class PebAccessor
    {
        private readonly PebData _pebData;

        private readonly Process _process;

        internal PebAccessor(Process process)
        {
            _process = process;

            _pebData = ReadPebData();
        }

        internal IEnumerable<Module> ReadModules()
        {
            if (_process.GetArchitecture() == Architecture.X86)
            {
                // Read the loader data of the PEB

                var loaderData = _process.ReadStructure<PebLdrData32>(_pebData.LoaderAddress);

                // Traverse the InMemoryOrder module list

                var currentEntryAddress = SafeHelpers.CreateSafeIntPtr(loaderData.InMemoryOrderModuleList.Flink);

                var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry32>("InMemoryOrderLinks");

                while (true)
                {
                    // Read the entry

                    var entryAddress = currentEntryAddress - (int) inMemoryOrderLinksOffset;

                    var entry = _process.ReadStructure<LdrDataTableEntry32>(entryAddress);

                    // Read the file path of the entry

                    var entryFilePathAddress = SafeHelpers.CreateSafeIntPtr(entry.FullDllName.Buffer);

                    var entryFilePathBuffer = _process.ReadBuffer<byte>(entryFilePathAddress, entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBuffer);

                    if (Environment.Is64BitOperatingSystem)
                    {
                        // Redirect the file path to the WOW64 system directory

                        entryFilePath = entryFilePath.Replace("System32", "SysWOW64", StringComparison.OrdinalIgnoreCase);
                    }

                    // Read the name of the entry

                    var entryNameAddress = SafeHelpers.CreateSafeIntPtr(entry.BaseDllName.Buffer);

                    var entryNameBuffer = _process.ReadBuffer<byte>(entryNameAddress, entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBuffer);

                    yield return new Module(SafeHelpers.CreateSafeIntPtr(entry.DllBase), entryFilePath, entryName);

                    if ((int) currentEntryAddress == loaderData.InMemoryOrderModuleList.Blink)
                    {
                        break;
                    }

                    // Set the address of the next entry

                    currentEntryAddress = SafeHelpers.CreateSafeIntPtr(entry.InMemoryOrderLinks.Flink);
                }
            }

            else
            {
                // Read the loader data of the PEB

                var loaderData = _process.ReadStructure<PebLdrData64>(_pebData.LoaderAddress);

                // Traverse the InMemoryOrder module list

                var currentEntryAddress = SafeHelpers.CreateSafeIntPtr(loaderData.InMemoryOrderModuleList.Flink);

                var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry64>("InMemoryOrderLinks");

                while (true)
                {
                    // Read the entry

                    var entryAddress = currentEntryAddress - (int) inMemoryOrderLinksOffset;

                    var entry = _process.ReadStructure<LdrDataTableEntry64>(entryAddress);

                    // Read the file path of the entry

                    var entryFilePathAddress = SafeHelpers.CreateSafeIntPtr(entry.FullDllName.Buffer);

                    var entryFilePathBuffer = _process.ReadBuffer<byte>(entryFilePathAddress, entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBuffer);

                    // Read the name of the entry

                    var entryNameAddress = SafeHelpers.CreateSafeIntPtr(entry.BaseDllName.Buffer);

                    var entryNameBuffer = _process.ReadBuffer<byte>(entryNameAddress, entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBuffer);

                    yield return new Module(SafeHelpers.CreateSafeIntPtr(entry.DllBase), entryFilePath, entryName);

                    if ((long) currentEntryAddress == loaderData.InMemoryOrderModuleList.Blink)
                    {
                        break;
                    }

                    // Set the address of the next entry

                    currentEntryAddress = SafeHelpers.CreateSafeIntPtr(entry.InMemoryOrderLinks.Flink);
                }
            }
        }

        internal string ResolveApiSetName(string apiSetName)
        {
            // Read the namespace

            var @namespace = _process.ReadStructure<ApiSetNamespace>(_pebData.ApiSetMapAddress);

            // Hash the name, skipping the patch number and prefix

            var charactersToHash = apiSetName.LastIndexOf("-", StringComparison.Ordinal);

            var nameHash = 0;

            for (var characterIndex = 0; characterIndex < charactersToHash; characterIndex += 1)
            {
                nameHash = nameHash * @namespace.HashFactor + char.ToLower(apiSetName[characterIndex]);
            }

            // Traverse the namespace for the corresponding entry

            ApiSetNamespaceEntry namespaceEntry;

            var minimumNamespaceEntryIndex = 0;

            var maximumNamespaceEntryIndex = @namespace.Count - 1;

            while (true)
            {
                if (maximumNamespaceEntryIndex < minimumNamespaceEntryIndex)
                {
                    throw new ApplicationException("Failed to resolve the name of an API set");
                }

                var middleNamespaceEntryIndex = (minimumNamespaceEntryIndex + maximumNamespaceEntryIndex) / 2;

                // Read the hash entry

                var hashEntryAddress = _pebData.ApiSetMapAddress + @namespace.HashOffset + middleNamespaceEntryIndex * Unsafe.SizeOf<ApiSetHashEntry>();

                var hashEntry = _process.ReadStructure<ApiSetHashEntry>(hashEntryAddress);

                if (nameHash == hashEntry.Hash)
                {
                    // Read the namespace entry

                    var namespaceEntryAddress = _pebData.ApiSetMapAddress + @namespace.EntryOffset + hashEntry.Index * Unsafe.SizeOf<ApiSetNamespaceEntry>();

                    namespaceEntry = _process.ReadStructure<ApiSetNamespaceEntry>(namespaceEntryAddress);

                    break;
                }

                if ((uint) nameHash < (uint) hashEntry.Hash)
                {
                    maximumNamespaceEntryIndex = middleNamespaceEntryIndex - 1;
                }

                else
                {
                    minimumNamespaceEntryIndex = middleNamespaceEntryIndex + 1;
                }
            }

            // Read the value entry that the namespace entry maps to

            var valueEntryAddress = _pebData.ApiSetMapAddress + namespaceEntry.ValueOffset;

            var valueEntry = _process.ReadStructure<ApiSetValueEntry>(valueEntryAddress);

            // Read the name of the value entry

            var valueEntryNameAddress = _pebData.ApiSetMapAddress + valueEntry.ValueOffset;

            var valueEntryNameBuffer = _process.ReadBuffer<byte>(valueEntryNameAddress, valueEntry.ValueCount);

            return Encoding.Unicode.GetString(valueEntryNameBuffer);
        }

        private PebData ReadPebData()
        {
            if (_process.GetArchitecture() == Architecture.X86)
            {
                Span<byte> pebAddressBuffer = stackalloc byte[IntPtr.Size];

                // Query the process for the address of its WOW64 PEB

                var ntStatus = Ntdll.NtQueryInformationProcess(_process.SafeHandle, ProcessInformationClass.Wow64Information, out pebAddressBuffer[0], pebAddressBuffer.Length, out _);

                if (ntStatus != NtStatus.Success)
                {
                    throw new Win32Exception(Ntdll.RtlNtStatusToDosError(ntStatus));
                }

                var pebAddress = MemoryMarshal.Read<IntPtr>(pebAddressBuffer);

                // Read the WOW64 PEB

                var peb = _process.ReadStructure<Peb32>(pebAddress);

                return new PebData(SafeHelpers.CreateSafeIntPtr(peb.ApiSetMap), SafeHelpers.CreateSafeIntPtr(peb.Ldr));
            }

            else
            {
                Span<byte> basicInformationBuffer = stackalloc byte[Unsafe.SizeOf<ProcessBasicInformation64>()];

                // Query the process for its basic information

                var ntStatus = Ntdll.NtQueryInformationProcess(_process.SafeHandle, ProcessInformationClass.BasicInformation, out basicInformationBuffer[0], basicInformationBuffer.Length, out _);

                if (ntStatus != NtStatus.Success)
                {
                    throw new Win32Exception(Ntdll.RtlNtStatusToDosError(ntStatus));
                }

                var basicInformation = MemoryMarshal.Read<ProcessBasicInformation64>(basicInformationBuffer);

                // Read the PEB

                var peb = _process.ReadStructure<Peb64>(SafeHelpers.CreateSafeIntPtr(basicInformation.PebBaseAddress));

                return new PebData(SafeHelpers.CreateSafeIntPtr(peb.ApiSetMap), SafeHelpers.CreateSafeIntPtr(peb.Ldr));
            }
        }
    }
}