using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Native.Structs;
using Lunar.PortableExecutable.Records;

namespace Lunar.PortableExecutable.DataDirectories;

internal sealed class ExportDirectory : DataDirectoryBase
{
    internal ExportDirectory(PEHeaders headers, Memory<byte> imageBytes) : base(headers.PEHeader!.ExportTableDirectory, headers, imageBytes) { }

    internal ExportedFunction? GetExportedFunction(string functionName)
    {
        if (!IsValid)
        {
            return null;
        }

        // Read the export directory

        var exportDirectory = MemoryMarshal.Read<ImageExportDirectory>(ImageBytes.Span[DirectoryOffset..]);

        // Search the name table for the function

        var low = 0;
        var high = exportDirectory.NumberOfNames - 1;

        while (low <= high)
        {
            var middle = (low + high) / 2;

            // Read the current name

            var currentNameOffsetOffset = RvaToOffset(exportDirectory.AddressOfNames) + sizeof(int) * middle;
            var currentNameOffset = RvaToOffset(MemoryMarshal.Read<int>(ImageBytes.Span[currentNameOffsetOffset..]));
            var currentNameLength = ImageBytes.Span[currentNameOffset..].IndexOf(byte.MinValue);
            var currentName = Encoding.UTF8.GetString(ImageBytes.Span.Slice(currentNameOffset, currentNameLength));

            if (functionName.Equals(currentName, StringComparison.OrdinalIgnoreCase))
            {
                // Read the function ordinal

                var functionOrdinalOffset = RvaToOffset(exportDirectory.AddressOfNameOrdinals) + sizeof(short) * middle;
                var functionOrdinal = MemoryMarshal.Read<short>(ImageBytes.Span[functionOrdinalOffset..]) + exportDirectory.Base;

                return GetExportedFunction(functionOrdinal);
            }

            // Adjust high/low according to binary search rules

            if (string.CompareOrdinal(functionName, currentName) < 0)
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

    internal ExportedFunction? GetExportedFunction(int functionOrdinal)
    {
        if (!IsValid)
        {
            return null;
        }

        // Read the export directory

        var exportDirectory = MemoryMarshal.Read<ImageExportDirectory>(ImageBytes.Span[DirectoryOffset..]);

        if ((functionOrdinal -= exportDirectory.Base) >= exportDirectory.NumberOfFunctions)
        {
            return null;
        }

        // Read the function address

        var functionAddressOffset = RvaToOffset(exportDirectory.AddressOfFunctions) + sizeof(int) * functionOrdinal;
        var functionAddress = MemoryMarshal.Read<int>(ImageBytes.Span[functionAddressOffset..]);

        // Check if the function is forwarded

        var exportDirectoryStartAddress = Headers.PEHeader!.ExportTableDirectory.RelativeVirtualAddress;
        var exportDirectoryEndAddress = exportDirectoryStartAddress + Headers.PEHeader!.ExportTableDirectory.Size;

        if (functionAddress < exportDirectoryStartAddress || functionAddress > exportDirectoryEndAddress)
        {
            return new ExportedFunction(null, functionAddress);
        }

        // Read the forwarder string

        var forwarderStringOffset = RvaToOffset(functionAddress);
        var forwarderStringLength = ImageBytes.Span[forwarderStringOffset..].IndexOf(byte.MinValue);
        var forwarderString = Encoding.UTF8.GetString(ImageBytes.Span.Slice(forwarderStringOffset, forwarderStringLength));

        return new ExportedFunction(forwarderString, functionAddress);
    }
}