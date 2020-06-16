using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class ExportDirectory : DataDirectory
    {
        internal IEnumerable<ExportedFunction> ExportedFunctions { get; }

        internal ExportDirectory(Memory<byte> imageBlock, PEHeaders headers) : base(imageBlock, headers)
        {
            ExportedFunctions = ReadExportedFunctions();
        }

        private IEnumerable<ExportedFunction> ReadExportedFunctions()
        {
            if (!Headers.TryGetDirectoryOffset(Headers.PEHeader.ExportTableDirectory, out var exportDirectoryOffset))
            {
                yield break;
            }

            // Read the export directory

            var exportDirectory = ReadStructure<ImageExportDirectory>(exportDirectoryOffset);

            var functionNamesRvasBaseOffset = RvaToOffset(exportDirectory.AddressOfNames);

            var functionOrdinalsBaseOffset = RvaToOffset(exportDirectory.AddressOfNameOrdinals);

            var functionRvasBaseOffset = RvaToOffset(exportDirectory.AddressOfFunctions);

            for (var functionIndex = 0; functionIndex < exportDirectory.NumberOfNames; functionIndex += 1)
            {
                // Read the name of the exported function

                var functionNameOffsetRvaOffset = functionNamesRvasBaseOffset + sizeof(int) * functionIndex;

                var functionNameOffsetRva = ReadStructure<int>(functionNameOffsetRvaOffset);

                var functionNameOffset = RvaToOffset(functionNameOffsetRva);

                var functionName = ReadNullTerminatedString(functionNameOffset);

                // Read the ordinal of the exported function

                var functionOrdinalOffset = functionOrdinalsBaseOffset + sizeof(short) * functionIndex;

                var functionOrdinal = ReadStructure<short>(functionOrdinalOffset);

                // Read the relative virtual address of the function

                var functionRvaOffset = functionRvasBaseOffset + sizeof(int) * functionOrdinal;

                var functionRva = ReadStructure<int>(functionRvaOffset);

                // Check if the exported function is forwarded

                var exportDirectoryStartOffset = Headers.PEHeader.ExportTableDirectory.RelativeVirtualAddress;

                var exportDirectoryEndOffset = exportDirectoryStartOffset + Headers.PEHeader.ExportTableDirectory.Size;

                if (functionRva < exportDirectoryStartOffset || functionRva > exportDirectoryEndOffset)
                {
                    yield return new ExportedFunction(null, functionName, exportDirectory.Base + functionOrdinal, functionRva);

                    continue;
                }

                // Read the forwarder string

                var forwarderStringOffset = RvaToOffset(functionRva);

                var forwarderString = ReadNullTerminatedString(forwarderStringOffset);

                yield return new ExportedFunction(forwarderString, functionName, exportDirectory.Base + functionOrdinal, functionRva);
            }
        }
    }
}