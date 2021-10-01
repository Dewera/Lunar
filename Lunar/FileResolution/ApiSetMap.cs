using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native.PInvoke;
using Lunar.Native.Structs;
using Lunar.Utilities;

namespace Lunar.FileResolution
{
    internal sealed class ApiSetMap
    {
        private readonly IntPtr _apiSetMapAddress;

        internal ApiSetMap()
        {
            _apiSetMapAddress = GetNativeAddress();
        }

        internal string? ResolveApiSetName(string apiSetName)
        {
            // Read the namespace of the API set

            var @namespace = Marshal.PtrToStructure<ApiSetNamespace>(_apiSetMapAddress);

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

                var hashEntryAddress = _apiSetMapAddress + @namespace.HashOffset + Unsafe.SizeOf<ApiSetHashEntry>() * middle;
                var hashEntry = Marshal.PtrToStructure<ApiSetHashEntry>(hashEntryAddress);

                if (apiSetNameHash == hashEntry.Hash)
                {
                    // Read the namespace entry

                    var namespaceEntryAddress = _apiSetMapAddress + @namespace.EntryOffset + Unsafe.SizeOf<ApiSetNamespaceEntry>() * hashEntry.Index;
                    var namespaceEntry = Marshal.PtrToStructure<ApiSetNamespaceEntry>(namespaceEntryAddress);

                    // Read the first value entry that the namespace entry maps to

                    var valueEntryAddress = _apiSetMapAddress + namespaceEntry.ValueOffset;
                    var valueEntry = Marshal.PtrToStructure<ApiSetValueEntry>(valueEntryAddress);

                    // Read the value entry name

                    var valueEntryNameAddress = _apiSetMapAddress + valueEntry.ValueOffset;
                    var valueEntryName = Marshal.PtrToStringUni(valueEntryNameAddress, valueEntry.ValueCount / sizeof(char));

                    return valueEntryName;
                }

                // Adjust high/low according to binary search rules

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

        private static IntPtr GetNativeAddress()
        {
            var pebAddress = Ntdll.RtlGetCurrentPeb();

            if (Environment.Is64BitProcess)
            {
                var peb = Marshal.PtrToStructure<Peb64>(pebAddress);

                return UnsafeHelpers.WrapPointer(peb.ApiSetMap);
            }

            else
            {
                var peb = Marshal.PtrToStructure<Peb32>(pebAddress);

                return UnsafeHelpers.WrapPointer(peb.ApiSetMap);
            }
        }
    }
}