using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class ImportDirectory : DataDirectory
    {
        internal ImmutableArray<ImportDescriptor> ImportDescriptors { get; }

        internal ImportDirectory(ReadOnlyMemory<byte> peBytes, PEHeaders peHeaders) : base(peBytes, peHeaders)
        {
            ImportDescriptors = ReadImportDescriptors().ToImmutableArray();
        }

        private IEnumerable<ImportDescriptor> ReadImportDescriptors()
        {
            // Calculate the import table offset

            if (!PeHeaders.TryGetDirectoryOffset(PeHeaders.PEHeader.ImportTableDirectory, out var importTableOffset))
            {
                yield break;
            }

            for (var descriptorIndex = 0;; descriptorIndex ++)
            {
                // Read the import descriptor

                var descriptorOffset = importTableOffset + Unsafe.SizeOf<ImageImportDescriptor>() * descriptorIndex;

                var descriptor = MemoryMarshal.Read<ImageImportDescriptor>(PeBytes.Slice(descriptorOffset).Span);

                if (descriptor.Name == 0)
                {
                    break;
                }

                // Read the import descriptor name

                var descriptorNameOffset = RvaToOffset(descriptor.Name);

                var descriptorName = ReadNullTerminatedString(descriptorNameOffset);

                // Read the functions imported under the import descriptor

                var descriptorThunkOffset = descriptor.OriginalFirstThunk == 0 ? RvaToOffset(descriptor.FirstThunk) : RvaToOffset(descriptor.OriginalFirstThunk);

                var importAddressTableOffset = RvaToOffset(descriptor.FirstThunk);

                var importedFunctions = ReadImportedFunctions(descriptorThunkOffset, importAddressTableOffset);

                yield return new ImportDescriptor(importedFunctions, descriptorName);
            }
        }

        private IEnumerable<ImportedFunction> ReadImportedFunctions(int descriptorThunkOffset, int importAddressTableOffset)
        {
            for (var functionIndex = 0;; functionIndex ++)
            {
                int functionOffset;

                int functionDataOffset;

                if (PeHeaders.PEHeader.Magic == PEMagic.PE32)
                {
                    // Read the thunk data of the function

                    var functionThunkDataOffset = descriptorThunkOffset + sizeof(int) * functionIndex;

                    var functionThunkData = MemoryMarshal.Read<int>(PeBytes.Slice(functionThunkDataOffset).Span);

                    if (functionThunkData == 0)
                    {
                        break;
                    }

                    // Calculate the offset of the function

                    functionOffset = importAddressTableOffset + sizeof(int) * functionIndex;

                    // Determine if the function is imported via ordinal

                    if ((functionThunkData & int.MinValue) != 0)
                    {
                        yield return new ImportedFunction(null, functionOffset, functionThunkData & ushort.MaxValue);

                        continue;
                    }

                    functionDataOffset = RvaToOffset(functionThunkData);
                }

                else
                {
                    // Read the thunk data of the function

                    var functionThunkDataOffset = descriptorThunkOffset + sizeof(long) * functionIndex;

                    var functionThunkData = MemoryMarshal.Read<long>(PeBytes.Slice(functionThunkDataOffset).Span);

                    if (functionThunkData == 0)
                    {
                        break;
                    }

                    // Calculate the offset of the function

                    functionOffset = importAddressTableOffset + sizeof(long) * functionIndex;

                    // Determine if the function is imported via ordinal

                    if ((functionThunkData & long.MinValue) != 0)
                    {
                        yield return new ImportedFunction(null, functionOffset, (int) functionThunkData & ushort.MaxValue);

                        continue;
                    }

                    functionDataOffset = RvaToOffset((int) functionThunkData);
                }

                // Read the name of the function

                var functionName = ReadNullTerminatedString(functionDataOffset + sizeof(short));

                // Read the ordinal of the function

                var functionOrdinal = MemoryMarshal.Read<short>(PeBytes.Slice(functionDataOffset).Span);

                yield return new ImportedFunction(functionName, functionOffset, functionOrdinal);
            }
        }
    }
}