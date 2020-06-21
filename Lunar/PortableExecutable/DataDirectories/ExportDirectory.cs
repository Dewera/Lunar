using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class ExportDirectory : DataDirectory
    {
        internal IEnumerable<ExportedFunction> ExportedFunctions { get; }

        internal ExportDirectory(PEHeaders headers, Memory<byte> imageBlock) : base(headers, imageBlock)
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

            var exportDirectory = MemoryMarshal.Read<ImageExportDirectory>(ImageBlock.Span.Slice(exportDirectoryOffset));

            var functionNamesRvasBaseOffset = RvaToOffset(exportDirectory.AddressOfNames);

            var functionOrdinalsBaseOffset = RvaToOffset(exportDirectory.AddressOfNameOrdinals);

            var functionRvasBaseOffset = RvaToOffset(exportDirectory.AddressOfFunctions);

            for (var functionIndex = 0; functionIndex < exportDirectory.NumberOfNames; functionIndex += 1)
            {
                // Read the name of the exported function

                var functionNameOffsetRvaOffset = functionNamesRvasBaseOffset + functionIndex * sizeof(int);

                var functionNameOffsetRva = MemoryMarshal.Read<int>(ImageBlock.Span.Slice(functionNameOffsetRvaOffset));

                var functionNameOffset = RvaToOffset(functionNameOffsetRva);

                var functionName = ReadString(functionNameOffset);

                // Read the ordinal of the exported function

                var functionOrdinalOffset = functionOrdinalsBaseOffset + functionIndex * sizeof(short);

                var functionOrdinal = MemoryMarshal.Read<short>(ImageBlock.Span.Slice(functionOrdinalOffset));

                // Read the relative virtual address of the function

                var functionRvaOffset = functionRvasBaseOffset + functionOrdinal * sizeof(int);

                var functionRva = MemoryMarshal.Read<int>(ImageBlock.Span.Slice(functionRvaOffset));

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

                var forwarderString = ReadString(forwarderStringOffset);

                yield return new ExportedFunction(forwarderString, functionName, exportDirectory.Base + functionOrdinal, functionRva);
            }
        }
    }
}