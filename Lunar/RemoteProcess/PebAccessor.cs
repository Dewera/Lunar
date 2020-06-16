using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Extensions;
using Lunar.Native.Enumerations;
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

                var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry32>("InMemoryOrderLinks");

                while (true)
                {
                    // Read the loader entry

                    var entryAddress = currentEntryAddress - inMemoryOrderLinksOffset.ToInt32();

                    var entry = _process.ReadStructure<LdrDataTableEntry32>(entryAddress);

                    // Read the file path of the entry

                    var entryFilePathAddress = new IntPtr(entry.FullDllName.Buffer);

                    var entryFilePathBlock = _process.ReadArray<byte>(entryFilePathAddress, entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBlock);

                    if (Environment.Is64BitOperatingSystem)
                    {
                        // Redirect the file path to the WOW64 system directory

                        entryFilePath = entryFilePath.Replace("System32", "SysWOW64", StringComparison.OrdinalIgnoreCase);
                    }

                    // Read the name of the loader entry

                    var entryNameAddress = new IntPtr(entry.BaseDllName.Buffer);

                    var entryNameBlock = _process.ReadArray<byte>(entryNameAddress, entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBlock);

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

                var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry64>("InMemoryOrderLinks");

                while (true)
                {
                    // Read the loader entry

                    var entryAddress = currentEntryAddress - inMemoryOrderLinksOffset.ToInt32();

                    var entry = _process.ReadStructure<LdrDataTableEntry64>(entryAddress);

                    // Read the file path of the entry

                    var entryFilePathAddress = new IntPtr(entry.FullDllName.Buffer);

                    var entryFilePathBlock = _process.ReadArray<byte>(entryFilePathAddress, entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBlock);

                    // Read the name of the loader entry

                    var entryNameAddress = new IntPtr(entry.BaseDllName.Buffer);

                    var entryNameBlock = _process.ReadArray<byte>(entryNameAddress, entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBlock);

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

                var hashEntryAddress = _pebData.ApiSetMapAddress + @namespace.HashOffset + middleNamespaceEntryIndex * Unsafe.SizeOf<ApiSetHashEntry>();

                var hashEntry = _process.ReadStructure<ApiSetHashEntry>(hashEntryAddress);

                if (nameHash == hashEntry.Hash)
                {
                    // Read the API set namespace entry

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

            // Read the API set value entry that the API set namespace entry maps to

            var valueEntryAddress = _pebData.ApiSetMapAddress + namespaceEntry.ValueOffset;

            var valueEntry = _process.ReadStructure<ApiSetValueEntry>(valueEntryAddress);

            // Read the name of the API set value entry

            var valueEntryNameAddress = _pebData.ApiSetMapAddress + valueEntry.ValueOffset;

            var valueEntryNameBlock = _process.ReadArray<byte>(valueEntryNameAddress, valueEntry.ValueCount);

            return Encoding.Unicode.GetString(valueEntryNameBlock);
        }

        private PebData ReadPebData()
        {
            if (_process.GetArchitecture() == Architecture.X86)
            {
                IntPtr pebAddress;

                if (Environment.Is64BitOperatingSystem)
                {
                    // Query the process for the address of its WOW64 PEB

                    pebAddress = _process.QueryInformation<IntPtr>(ProcessInformationClass.Wow64Information);
                }

                else
                {
                    // Query the process for its BasicInformation

                    var basicInformation = _process.QueryInformation<ProcessBasicInformation32>(ProcessInformationClass.BasicInformation);

                    pebAddress = new IntPtr(basicInformation.PebBaseAddress);
                }

                // Read the PEB

                var peb = _process.ReadStructure<Peb32>(pebAddress);

                return new PebData(new IntPtr(peb.ApiSetMap), new IntPtr(peb.Ldr));
            }

            else
            {
                // Query the process for its BasicInformation

                var basicInformation = _process.QueryInformation<ProcessBasicInformation64>(ProcessInformationClass.BasicInformation);

                // Read the PEB

                var peb = _process.ReadStructure<Peb64>(new IntPtr(basicInformation.PebBaseAddress));

                return new PebData(new IntPtr(peb.ApiSetMap), new IntPtr(peb.Ldr));
            }
        }
    }
}