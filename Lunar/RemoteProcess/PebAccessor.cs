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

                var currentEntryAddress = new IntPtr(loaderData.InMemoryOrderModuleList.Flink);

                var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry32>("InMemoryOrderLinks").ToInt32();

                while (true)
                {
                    // Read the loader entry

                    var entry = _process.ReadStructure<LdrDataTableEntry32>(currentEntryAddress - inMemoryOrderLinksOffset);

                    // Read the file path of the entry

                    var entryFilePathAddress = new IntPtr(entry.FullDllName.Buffer);

                    var entryFilePathBytes = _process.ReadBuffer<byte>(entryFilePathAddress, entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    if (Environment.Is64BitOperatingSystem)
                    {
                        // Redirect the file path to the WOW64 system directory

                        entryFilePath = entryFilePath.Replace("System32", "SysWOW64", StringComparison.OrdinalIgnoreCase);
                    }

                    // Read the name of the loader entry

                    var entryNameAddress = new IntPtr(entry.BaseDllName.Buffer);

                    var entryNameBytes = _process.ReadBuffer<byte>(entryNameAddress, entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes);

                    yield return new Module(new IntPtr(entry.DllBase), entryFilePath, entryName);

                    if (currentEntryAddress.ToInt32() == loaderData.InMemoryOrderModuleList.Blink)
                    {
                        break;
                    }

                    currentEntryAddress = new IntPtr(entry.InMemoryOrderLinks.Flink);
                }
            }

            else
            {
                // Read the loader data of the PEB

                var loaderData = _process.ReadStructure<PebLdrData64>(_pebData.LoaderAddress);

                // Traverse the InMemoryOrder module list

                var currentEntryAddress = new IntPtr(loaderData.InMemoryOrderModuleList.Flink);

                var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry64>("InMemoryOrderLinks").ToInt32();

                while (true)
                {
                    // Read the loader entry

                    var entry = _process.ReadStructure<LdrDataTableEntry64>(currentEntryAddress - inMemoryOrderLinksOffset);

                    // Read the file path of the entry

                    var entryFilePathAddress = new IntPtr(entry.FullDllName.Buffer);

                    var entryFilePathBytes = _process.ReadBuffer<byte>(entryFilePathAddress, entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    // Read the name of the loader entry

                    var entryNameAddress = new IntPtr(entry.BaseDllName.Buffer);

                    var entryNameBytes = _process.ReadBuffer<byte>(entryNameAddress, entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes);

                    yield return new Module(new IntPtr(entry.DllBase), entryFilePath, entryName);

                    if (currentEntryAddress.ToInt64() == loaderData.InMemoryOrderModuleList.Blink)
                    {
                        break;
                    }

                    currentEntryAddress = new IntPtr(entry.InMemoryOrderLinks.Flink);
                }
            }
        }

        internal string ResolveApiSetName(string apiSetName)
        {
            // Read the API set namespace

            var @namespace = _process.ReadStructure<ApiSetNamespace>(_pebData.ApiSetMapAddress);

            // Hash the API set name, skipping the patch number and prefix

            var charactersToHash = apiSetName.LastIndexOf("-", StringComparison.Ordinal);

            var nameHash = 0;

            for (var characterIndex = 0; characterIndex < charactersToHash; characterIndex += 1)
            {
                nameHash = nameHash * @namespace.HashFactor + char.ToLower(apiSetName[characterIndex]);
            }

            // Traverse the API set namespace for the corresponding namespace entry

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

                // Read the API set hash entry

                var hashEntryAddress = _pebData.ApiSetMapAddress + @namespace.HashOffset + Unsafe.SizeOf<ApiSetHashEntry>() * middleNamespaceEntryIndex;

                var hashEntry = _process.ReadStructure<ApiSetHashEntry>(hashEntryAddress);

                if (nameHash == hashEntry.Hash)
                {
                    // Read the API set namespace entry

                    var namespaceEntryAddress = _pebData.ApiSetMapAddress + @namespace.EntryOffset + Unsafe.SizeOf<ApiSetNamespaceEntry>() * hashEntry.Index;

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

            // Read the API set value entry that the API set namespace entry maps to

            var valueEntryAddress = _pebData.ApiSetMapAddress + namespaceEntry.ValueOffset;

            var valueEntry = _process.ReadStructure<ApiSetValueEntry>(valueEntryAddress);

            // Read the name of the API set value entry

            var valueEntryNameAddress = _pebData.ApiSetMapAddress + valueEntry.ValueOffset;

            var valueEntryNameBytes = _process.ReadBuffer<byte>(valueEntryNameAddress, valueEntry.ValueCount);

            return Encoding.Unicode.GetString(valueEntryNameBytes);
        }

        private PebData ReadPebData()
        {
            if (_process.GetArchitecture() == Architecture.X86)
            {
                IntPtr pebAddress;

                if (Environment.Is64BitOperatingSystem)
                {
                    // Query the process for the address of its WOW64 PEB

                    Span<byte> pebAddressBytes = stackalloc byte[IntPtr.Size];

                    var ntStatus = Ntdll.NtQueryInformationProcess(_process.SafeHandle, ProcessInformationClass.Wow64Information, out pebAddressBytes[0], pebAddressBytes.Length, out _);

                    if (ntStatus != NtStatus.Success)
                    {
                        throw new Win32Exception(Ntdll.RtlNtStatusToDosError(ntStatus));
                    }

                    pebAddress = MemoryMarshal.Read<IntPtr>(pebAddressBytes);
                }

                else
                {
                    // Query the process for its BasicInformation

                    Span<byte> basicInformationBytes = stackalloc byte[Unsafe.SizeOf<ProcessBasicInformation32>()];

                    var ntStatus = Ntdll.NtQueryInformationProcess(_process.SafeHandle, ProcessInformationClass.BasicInformation, out basicInformationBytes[0], basicInformationBytes.Length, out _);

                    if (ntStatus != NtStatus.Success)
                    {
                        throw new Win32Exception(Ntdll.RtlNtStatusToDosError(ntStatus));
                    }

                    var basicInformation = MemoryMarshal.Read<ProcessBasicInformation32>(basicInformationBytes);

                    pebAddress = new IntPtr(basicInformation.PebBaseAddress);
                }

                // Read the PEB

                var peb = _process.ReadStructure<Peb32>(pebAddress);

                return new PebData(new IntPtr(peb.ApiSetMap), new IntPtr(peb.Ldr));
            }

            else
            {
                // Query the process for its BasicInformation

                Span<byte> basicInformationBytes = stackalloc byte[Unsafe.SizeOf<ProcessBasicInformation64>()];

                var ntStatus = Ntdll.NtQueryInformationProcess(_process.SafeHandle, ProcessInformationClass.BasicInformation, out basicInformationBytes[0], basicInformationBytes.Length, out _);

                if (ntStatus != NtStatus.Success)
                {
                    throw new Win32Exception(Ntdll.RtlNtStatusToDosError(ntStatus));
                }

                var basicInformation = MemoryMarshal.Read<ProcessBasicInformation64>(basicInformationBytes);

                // Read the PEB

                var peb = _process.ReadStructure<Peb64>(new IntPtr(basicInformation.PebBaseAddress));

                return new PebData(new IntPtr(peb.ApiSetMap), new IntPtr(peb.Ldr));
            }
        }
    }
}