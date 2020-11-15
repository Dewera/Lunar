using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Extensions;
using Lunar.Native.Enumerations;
using Lunar.Native.Structures;
using Lunar.Shared;

namespace Lunar.Remote
{
    internal sealed class ApiSetMap
    {
        private readonly IntPtr _address;

        private readonly Process _process;

        internal ApiSetMap(Process process)
        {
            _address = GetApiSetMapAddress(process);

            _process = process;
        }

        internal string? ResolveApiSet(string apiSetName)
        {
            // Read the namespace

            var @namespace = _process.ReadStructure<ApiSetNamespace>(_address);

            // Create a hash for the API set name, skipping the patch number and suffix

            var charactersToHash = apiSetName[..apiSetName.LastIndexOf("-", StringComparison.Ordinal)];

            var apiSetNameHash = charactersToHash.Aggregate(0, (currentHash, character) => currentHash * @namespace.HashFactor + char.ToLower(character));

            // Search the namespace for the corresponding hash entry

            var low = 0;

            var high = @namespace.Count - 1;

            while (low <= high)
            {
                var middle = (low + high) / 2;

                // Read the hash entry

                var hashEntryAddress = _address + @namespace.HashOffset + Unsafe.SizeOf<ApiSetHashEntry>() * middle;

                var hashEntry = _process.ReadStructure<ApiSetHashEntry>(hashEntryAddress);

                if (apiSetNameHash == hashEntry.Hash)
                {
                    // Read the namespace entry

                    var namespaceEntryAddress = _address + @namespace.EntryOffset + Unsafe.SizeOf<ApiSetNamespaceEntry>() * hashEntry.Index;

                    var namespaceEntry = _process.ReadStructure<ApiSetNamespaceEntry>(namespaceEntryAddress);

                    // Read the first value entry that the namespace entry maps to

                    var valueEntryAddress = _address + namespaceEntry.ValueOffset;

                    var valueEntry = _process.ReadStructure<ApiSetValueEntry>(valueEntryAddress);

                    // Read the value entry name

                    var valueEntryNameAddress = _address + valueEntry.ValueOffset;

                    return Encoding.Unicode.GetString(_process.ReadArray<byte>(valueEntryNameAddress, valueEntry.ValueCount));
                }

                if ((uint) apiSetNameHash < (uint) hashEntry.Hash)
                {
                    high = middle - 1;
                }

                else
                {
                    low = middle + 1;
                }
            }

            return null;
        }

        private static IntPtr GetApiSetMapAddress(Process process)
        {
            if (process.GetArchitecture() == Architecture.X86)
            {
                IntPtr pebAddress;

                if (Environment.Is64BitOperatingSystem)
                {
                    // Query the process for the address of its WOW64 PEB

                    pebAddress = process.QueryInformation<IntPtr>(ProcessInformationType.Wow64Information);
                }

                else
                {
                    // Query the process for its basic information

                    var basicInformation = process.QueryInformation<ProcessBasicInformation32>(ProcessInformationType.BasicInformation);

                    pebAddress = SafeHelpers.CreateSafePointer(basicInformation.PebBaseAddress);
                }

                // Read the PEB

                var peb = process.ReadStructure<Peb32>(pebAddress);

                return SafeHelpers.CreateSafePointer(peb.ApiSetMap);
            }

            else
            {
                // Query the process for its basic information

                var basicInformation = process.QueryInformation<ProcessBasicInformation64>(ProcessInformationType.BasicInformation);

                var pebAddress = SafeHelpers.CreateSafePointer(basicInformation.PebBaseAddress);

                // Read the PEB

                var peb = process.ReadStructure<Peb64>(pebAddress);

                return SafeHelpers.CreateSafePointer(peb.ApiSetMap);
            }
        }
    }
}