using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class ImportDirectory : DataDirectory
    {
        internal IEnumerable<ImportDescriptor> ImportDescriptors { get; }

        internal ImportDirectory(PEHeaders headers, Memory<byte> imageBlock) : base(headers, imageBlock)
        {
            ImportDescriptors = ReadImportDescriptors();
        }

        private IEnumerable<ImportDescriptor> ReadImportDescriptors()
        {
            if (!Headers.TryGetDirectoryOffset(Headers.PEHeader.ImportTableDirectory, out var currentDescriptorOffset))
            {
                yield break;
            }

            while (true)
            {
                // Read the import descriptor

                var descriptor = MemoryMarshal.Read<ImageImportDescriptor>(ImageBlock.Span.Slice(currentDescriptorOffset));

                if (descriptor.FirstThunk == 0)
                {
                    break;
                }

                // Read the name of the import descriptor

                var descriptorNameOffset = RvaToOffset(descriptor.Name);

                var descriptorName = ReadString(descriptorNameOffset);

                // Read the functions imported under the import descriptor

                var currentIatOffset = RvaToOffset(descriptor.FirstThunk);

                var currentThunkOffset = descriptor.OriginalFirstThunk == 0 ? currentIatOffset : RvaToOffset(descriptor.OriginalFirstThunk);

                var functions = ReadImportedFunctions(currentIatOffset, currentThunkOffset);

                yield return new ImportDescriptor(functions, descriptorName);

                currentDescriptorOffset += Unsafe.SizeOf<ImageImportDescriptor>();
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