using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class ExportDirectory : DataDirectory
    {
        internal ImmutableArray<ExportedFunction> ExportedFunctions { get; }

        internal ExportDirectory(ReadOnlyMemory<byte> peBytes, PEHeaders peHeaders) : base(peBytes, peHeaders)
        {
            ExportedFunctions = ReadExportedFunctions().ToImmutableArray();
        }

        private IEnumerable<ExportedFunction> ReadExportedFunctions()
        {
            // Calculate the offset of the export table
            
            if (!PeHeaders.TryGetDirectoryOffset(PeHeaders.PEHeader.ExportTableDirectory, out var exportTableOffset))
            {
                yield break;
            }
            
            // Read the export table
            
            var exportTable = MemoryMarshal.Read<ImageExportDirectory>(PeBytes.Slice(exportTableOffset).Span);
            
            // Read the exported functions
            
            var functionNameBaseOffset = RvaToOffset(exportTable.AddressOfNames);

            var functionOffsetBaseOffset = RvaToOffset(exportTable.AddressOfFunctions);

            var functionOrdinalBaseOffset = RvaToOffset(exportTable.AddressOfNameOrdinals);

            for (var functionIndex = 0; functionIndex < exportTable.NumberOfNames; functionIndex ++)
            {
                // Read the name of the function
                
                var functionNameOffsetOffset = functionNameBaseOffset + sizeof(int) * functionIndex;

                var functionNameOffset = RvaToOffset(MemoryMarshal.Read<int>(PeBytes.Slice(functionNameOffsetOffset).Span));

                var functionName = ReadNullTerminatedString(functionNameOffset);
                
                // Read the ordinal of the function
                
                var functionOrdinalOffset = functionOrdinalBaseOffset + sizeof(short) * functionIndex;

                var functionOrdinal = MemoryMarshal.Read<short>(PeBytes.Slice(functionOrdinalOffset).Span);
                
                // Read the offset of the function
                
                var functionOffsetOffset = functionOffsetBaseOffset + sizeof(int) * functionOrdinal;

                var functionOffset = MemoryMarshal.Read<int>(PeBytes.Slice(functionOffsetOffset).Span);

                // Determine if the function is forwarded to another function
                
                var exportTableStartOffset = PeHeaders.PEHeader.ExportTableDirectory.RelativeVirtualAddress;

                var exportTableEndOffset = exportTableStartOffset + PeHeaders.PEHeader.ExportTableDirectory.Size;

                if (functionOffset < exportTableStartOffset || functionOffset > exportTableEndOffset)
                {
                    yield return new ExportedFunction(null, functionName, functionOffset, exportTable.Base + functionOrdinal);

                    continue;
                }
                
                // Read the forwarder string of the function
                
                var forwarderStringOffset = RvaToOffset(functionOffset);

                var forwarderString = ReadNullTerminatedString(forwarderStringOffset);
                
                yield return new ExportedFunction(forwarderString, functionName, functionOffset, exportTable.Base + functionOrdinal);
            }
        }
    }
}