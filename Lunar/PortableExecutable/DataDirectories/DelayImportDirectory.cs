using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class DelayImportDirectory : DataDirectory
    {
        internal IEnumerable<ImportDescriptor> DelayLoadImportDescriptors { get; }

        internal DelayImportDirectory(PEHeaders headers, Memory<byte> imageBlock) : base(headers, imageBlock)
        {
            DelayLoadImportDescriptors = ReadDelayLoadImportDescriptors();
        }

        private IEnumerable<ImportDescriptor> ReadDelayLoadImportDescriptors()
        {
            if (!Headers.TryGetDirectoryOffset(Headers.PEHeader.ImportTableDirectory, out var currentDescriptorOffset))
            {
                yield break;
            }

            while (true)
            {
                // Read the delay load import descriptor

                var descriptor = MemoryMarshal.Read<ImageDelayLoadDescriptor>(ImageBlock.Span.Slice(currentDescriptorOffset));

                if (descriptor.DllNameRva == 0)
                {
                    break;
                }

                // Read the name of the delay load import descriptor

                var descriptorNameOffset = RvaToOffset(descriptor.DllNameRva);

                var descriptorName = ReadString(descriptorNameOffset);

                // Read the functions imported under the delay load import descriptor

                var currentIatOffset = RvaToOffset(descriptor.ImportAddressTableRva);

                var currentThunkOffset = RvaToOffset(descriptor.ImportNameTableRva);

                var functions = ReadImportedFunctions(currentIatOffset, currentThunkOffset);

                yield return new ImportDescriptor(functions, descriptorName);

                currentDescriptorOffset += Unsafe.SizeOf<ImageDelayLoadDescriptor>();
            }
        }

        private IEnumerable<ImportedFunction> ReadImportedFunctions(int currentIatOffset, int currentThunkOffset)
        {
            while (true)
            {
                int functionDataOffset;

                if (Headers.PEHeader.Magic == PEMagic.PE32)
                {
                    // Read the thunk of the imported function

                    var functionThunk = MemoryMarshal.Read<int>(ImageBlock.Span.Slice(currentThunkOffset));

                    if (functionThunk == 0)
                    {
                        break;
                    }

                    // Check if the imported function is imported via ordinal

                    if ((functionThunk & int.MinValue) != 0)
                    {
                        yield return new ImportedFunction(currentIatOffset, null, functionThunk & ushort.MaxValue);

                        continue;
                    }

                    functionDataOffset = RvaToOffset(functionThunk);
                }

                else
                {
                    // Read the thunk of the imported function

                    var functionThunk = MemoryMarshal.Read<long>(ImageBlock.Span.Slice(currentThunkOffset));

                    if (functionThunk == 0)
                    {
                        break;
                    }

                    // Check if the imported function is imported via ordinal

                    if ((functionThunk & long.MinValue) != 0)
                    {
                        yield return new ImportedFunction(currentIatOffset, null, (int) functionThunk & ushort.MaxValue);

                        continue;
                    }

                    functionDataOffset = RvaToOffset((int) functionThunk);
                }

                // Read the name of the imported function

                var functionNameOffset = functionDataOffset + sizeof(short);

                var functionName = ReadString(functionNameOffset);

                // Read the ordinal of the imported function

                var functionOrdinal = MemoryMarshal.Read<short>(ImageBlock.Span.Slice(functionDataOffset));

                yield return new ImportedFunction(currentIatOffset, functionName, functionOrdinal);

                currentIatOffset += Headers.PEHeader.Magic == PEMagic.PE32 ? sizeof(int) : sizeof(long);

                currentThunkOffset += Headers.PEHeader.Magic == PEMagic.PE32 ? sizeof(int) : sizeof(long);
            }
        }
    }
}