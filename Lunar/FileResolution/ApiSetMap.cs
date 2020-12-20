using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native.PInvoke;
using Lunar.Native.Structures;
using Lunar.Utilities;

namespace Lunar.FileResolution
{
    internal sealed class ApiSetMap
    {
        private readonly IntPtr _address;

        internal ApiSetMap()
        {
            _address = GetApiSetMapAddress();
        }

        internal string? ResolveApiSet(string apiSetName)
        {
            // Read the namespace

            var @namespace = Marshal.PtrToStructure<ApiSetNamespace>(_address);

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

                var hashEntry = Marshal.PtrToStructure<ApiSetHashEntry>(hashEntryAddress);

                if (apiSetNameHash == hashEntry.Hash)
                {
                    // Read the namespace entry

                    var namespaceEntryAddress = _address + @namespace.EntryOffset + Unsafe.SizeOf<ApiSetNamespaceEntry>() * hashEntry.Index;

                    var namespaceEntry = Marshal.PtrToStructure<ApiSetNamespaceEntry>(namespaceEntryAddress);

                    // Read the first value entry that the namespace entry maps to

                    var valueEntryAddress = _address + namespaceEntry.ValueOffset;

                    var valueEntry = Marshal.PtrToStructure<ApiSetValueEntry>(valueEntryAddress);

                    // Read the value entry name

                    var valueEntryNameAddress = _address + valueEntry.ValueOffset;

                    var valueEntryName = Marshal.PtrToStringUni(valueEntryNameAddress, valueEntry.ValueCount / sizeof(char));

                    return valueEntryName;
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

        private static IntPtr GetApiSetMapAddress()
        {
            var pebAddress = Ntdll.RtlGetCurrentPeb();

            if (Environment.Is64BitProcess)
            {
                var peb = Marshal.PtrToStructure<Peb64>(pebAddress);

                return SafeHelpers.CreateSafePointer(peb.ApiSetMap);
            }

            else
            {
                var peb = Marshal.PtrToStructure<Peb32>(pebAddress);

                return SafeHelpers.CreateSafePointer(peb.ApiSetMap);
            }
        }
    }
}