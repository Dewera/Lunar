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
    internal sealed class DelayImportDirectory : DataDirectory
    {
        internal ImmutableArray<ImportDescriptor> DelayImportDescriptors { get; }

        internal DelayImportDirectory(ReadOnlyMemory<byte> peBytes, PEHeaders peHeaders) : base(peBytes, peHeaders)
        {
            DelayImportDescriptors = ReadDelayImportDescriptors().ToImmutableArray();
        }

        private IEnumerable<ImportDescriptor> ReadDelayImportDescriptors()
        {
            // Calculate the offset of the delay import table

            if (!PeHeaders.TryGetDirectoryOffset(PeHeaders.PEHeader.DelayImportTableDirectory, out var delayImportTableOffset))
            {
                yield break;
            }

            for (var descriptorIndex = 0;; descriptorIndex ++)
            {
                // Read the delay import descriptor

                var descriptorOffset = delayImportTableOffset + Unsafe.SizeOf<ImageDelayLoadDescriptor>() * descriptorIndex;

                var descriptor = MemoryMarshal.Read<ImageDelayLoadDescriptor>(PeBytes.Slice(descriptorOffset).Span);

                if (descriptor.DllNameRva == 0)
                {
                    break;
                }
                
                // Read the name of the delay import descriptor
                
                var descriptorNameOffset = RvaToOffset(descriptor.DllNameRva);

                var descriptorName = ReadNullTerminatedString(descriptorNameOffset);
                
                // Read the functions imported under the delay import descriptor
                
                var descriptorThunkOffset = RvaToOffset(descriptor.ImportNameTableRva);

                var importAddressTableOffset = RvaToOffset(descriptor.ImportAddressTableRva);

                var delayImportedFunctions = ReadDelayImportedFunctions(descriptorThunkOffset, importAddressTableOffset);
                
                yield return new ImportDescriptor(delayImportedFunctions, descriptorName);
            }
        }

        private IEnumerable<ImportedFunction> ReadDelayImportedFunctions(int descriptorThunkOffset, int importAddressTableOffset)
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