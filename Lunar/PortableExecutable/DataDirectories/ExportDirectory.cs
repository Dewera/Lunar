using System;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class ExportDirectory : DataDirectory
    {
        internal ExportDirectory(PEHeaders headers, Memory<byte> imageBytes) : base(headers, imageBytes, headers.PEHeader!.ExportTableDirectory) { }

        internal ExportedFunction? GetExportedFunction(string functionName)
        {
            if (!IsValid)
            {
                return null;
            }

            // Read the export directory

            var exportDirectory = MemoryMarshal.Read<ImageExportDirectory>(ImageBytes.Span.Slice(DirectoryOffset));

            // Read the name address table

            var nameAddressTableOffset = RvaToOffset(exportDirectory.AddressOfNames);

            var nameAddressTable = MemoryMarshal.Cast<byte, int>(ImageBytes.Span.Slice(nameAddressTableOffset, sizeof(int) * exportDirectory.NumberOfNames));

            // Search the name address table for the corresponding name

            var low = 0;

            var high = exportDirectory.NumberOfNames - 1;

            while (low <= high)
            {
                var middle = (low + high) / 2;

                // Read the name

                var nameOffset = RvaToOffset(nameAddressTable[middle]);

                var nameLength = ImageBytes.Span.Slice(nameOffset).IndexOf(byte.MinValue);

                var name = Encoding.UTF8.GetString(ImageBytes.Span.Slice(nameOffset, nameLength));

                if (functionName.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    // Read the name ordinal table

                    var ordinalTableOffset = RvaToOffset(exportDirectory.AddressOfNameOrdinals);

                    var ordinalTable = MemoryMarshal.Cast<byte, short>(ImageBytes.Span.Slice(ordinalTableOffset, sizeof(short) * exportDirectory.NumberOfNames));

                    var functionOrdinal = exportDirectory.Base + ordinalTable[middle];

                    return GetExportedFunction(functionOrdinal);
                }

                if (string.CompareOrdinal(functionName, name) < 0)
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

            var exportDirectory = MemoryMarshal.Read<ImageExportDirectory>(ImageBytes.Span.Slice(DirectoryOffset));

            functionOrdinal -= exportDirectory.Base;

            if (functionOrdinal >= exportDirectory.NumberOfFunctions)
            {
                return null;
            }

            // Read the address table

            var addressTableOffset = RvaToOffset(exportDirectory.AddressOfFunctions);

            var addressTable = MemoryMarshal.Cast<byte, int>(ImageBytes.Span.Slice(addressTableOffset, sizeof(int) * exportDirectory.NumberOfFunctions));

            var functionAddress = addressTable[functionOrdinal];

            // Check if the function is forwarded

            var exportDirectoryStartAddress = Headers.PEHeader!.ExportTableDirectory.RelativeVirtualAddress;

            var exportDirectoryEndAddress = exportDirectoryStartAddress + Headers.PEHeader!.ExportTableDirectory.Size;

            if (functionAddress < exportDirectoryStartAddress || functionAddress > exportDirectoryEndAddress)
            {
                return new ExportedFunction(null, functionAddress);
            }

            // Read the forwarder string

            var forwarderStringOffset = RvaToOffset(functionAddress);

            var forwarderStringLength = ImageBytes.Span.Slice(forwarderStringOffset).IndexOf(byte.MinValue);

            var forwarderString = Encoding.UTF8.GetString(ImageBytes.Span.Slice(forwarderStringOffset, forwarderStringLength));

            return new ExportedFunction(forwarderString, functionAddress);
        }
    }
}