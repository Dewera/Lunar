using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native.PInvoke;
using Lunar.Native.Structs;

namespace Lunar.FileResolution;

internal sealed class ApiSetMap
{
    private readonly nint _apiSetMapAddress;

    internal ApiSetMap()
    {
        _apiSetMapAddress = GetApiSetMapAddress();
    }

    internal string? ResolveApiSetName(string apiSetName, string? parentName)
    {
        // Read the API set namespace

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

                // Read the namespace entry name

                var namespaceEntryNameAddress = _apiSetMapAddress + namespaceEntry.NameOffset;
                var namespaceEntryName = Marshal.PtrToStringUni(namespaceEntryNameAddress, namespaceEntry.NameLength / sizeof(char));

                // Ensure the correct hash bucket is being used

                if (!charactersToHash.Equals(namespaceEntryName[..namespaceEntryName.LastIndexOf("-", StringComparison.Ordinal)]))
                {
                    break;
                }

                // Read the default value entry

                var valueEntryAddress = _apiSetMapAddress + namespaceEntry.ValueOffset;
                var valueEntry = Marshal.PtrToStructure<ApiSetValueEntry>(valueEntryAddress);

                // Read the default value entry name

                var valueEntryNameAddress = _apiSetMapAddress + valueEntry.ValueOffset;
                var valueEntryName = Marshal.PtrToStringUni(valueEntryNameAddress, valueEntry.ValueCount / sizeof(char));

                if (parentName is null || valueEntry.ValueCount == 1)
                {
                    return valueEntryName;
                }

                // Search for an alternative host using the parent

                for (var valueEntryIndex = namespaceEntry.ValueCount - 1; valueEntryIndex >= 0; valueEntryIndex -= 1)
                {
                    // Read the value entry

                    valueEntryAddress = _apiSetMapAddress + namespaceEntry.ValueOffset + Unsafe.SizeOf<ApiSetValueEntry>() * valueEntryIndex;
                    valueEntry = Marshal.PtrToStructure<ApiSetValueEntry>(valueEntryAddress);

                    // Read the value entry alias name

                    var valueEntryAliasNameAddress = _apiSetMapAddress + valueEntry.NameOffset;
                    var valueEntryAliasName = Marshal.PtrToStringUni(valueEntryAliasNameAddress, valueEntry.NameLength / sizeof(char));

                    if (parentName.Equals(valueEntryAliasName, StringComparison.OrdinalIgnoreCase))
                    {
                        // Read the value entry name

                        valueEntryNameAddress = _apiSetMapAddress + valueEntry.ValueOffset;
                        valueEntryName = Marshal.PtrToStringUni(valueEntryNameAddress, valueEntry.ValueCount / sizeof(char));

                        break;
                    }
                }

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

    private static nint GetApiSetMapAddress()
    {
        var pebAddress = Ntdll.RtlGetCurrentPeb();

        if (Environment.Is64BitProcess)
        {
            return (nint) Marshal.PtrToStructure<Peb64>(pebAddress).ApiSetMap;
        }

        return Marshal.PtrToStructure<Peb32>(pebAddress).ApiSetMap;
    }
}