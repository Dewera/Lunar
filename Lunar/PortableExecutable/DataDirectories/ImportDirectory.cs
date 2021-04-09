using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class ImportDirectory : DataDirectory
    {
        internal ImportDirectory(PEHeaders headers, Memory<byte> imageBytes) : base(headers.PEHeader!.ImportTableDirectory, headers, imageBytes) { }

        internal IEnumerable<ImportDescriptor> GetImportDescriptors()
        {
            if (!IsValid)
            {
                yield break;
            }

            for (var descriptorIndex = 0;; descriptorIndex += 1)
            {
                // Read the descriptor

                var descriptorOffset = DirectoryOffset + Unsafe.SizeOf<ImageImportDescriptor>() * descriptorIndex;

                var descriptor = MemoryMarshal.Read<ImageImportDescriptor>(ImageBytes.Span[descriptorOffset..]);

                if (descriptor.FirstThunk == 0)
                {
                    break;
                }

                // Read the descriptor name

                var descriptorNameOffset = RvaToOffset(descriptor.Name);

                var descriptorNameLength = ImageBytes.Span[descriptorNameOffset..].IndexOf(byte.MinValue);

                var descriptorName = Encoding.UTF8.GetString(ImageBytes.Span.Slice(descriptorNameOffset, descriptorNameLength));

                // Read the functions imported under the descriptor

                var offsetTableOffset = RvaToOffset(descriptor.FirstThunk);

                var thunkTableOffset = descriptor.OriginalFirstThunk == 0 ? offsetTableOffset : RvaToOffset(descriptor.OriginalFirstThunk);

                var functions = GetImportedFunctions(offsetTableOffset, thunkTableOffset);

                yield return new ImportDescriptor(functions, descriptorName);
            }
        }

        private IEnumerable<ImportedFunction> GetImportedFunctions(int offsetTableOffset, int thunkTableOffset)
        {
            for (var functionIndex = 0;; functionIndex += 1)
            {
                if (Headers.PEHeader!.Magic == PEMagic.PE32)
                {
                    var functionOffset = offsetTableOffset + sizeof(int) * functionIndex;

                    // Read the function thunk

                    var functionThunkOffset = thunkTableOffset + sizeof(int) * functionIndex;

                    var functionThunk = MemoryMarshal.Read<int>(ImageBytes.Span[functionThunkOffset..]);

                    if (functionThunk == 0)
                    {
                        break;
                    }

                    // Check if the function is imported via ordinal

                    if ((functionThunk & int.MinValue) != 0)
                    {
                        var functionOrdinal = functionThunk & ushort.MaxValue;

                        yield return new ImportedFunction(null, functionOffset, functionOrdinal);
                    }

                    else
                    {
                        // Read the function ordinal

                        var functionOrdinalOffset = RvaToOffset(functionThunk);

                        var functionOrdinal = MemoryMarshal.Read<short>(ImageBytes.Span[functionOrdinalOffset..]);

                        // Read the function name

                        var functionNameOffset = functionOrdinalOffset + sizeof(short);

                        var functionNameLength = ImageBytes.Span[functionNameOffset..].IndexOf(byte.MinValue);

                        var functionName = Encoding.UTF8.GetString(ImageBytes.Span.Slice(functionNameOffset, functionNameLength));

                        yield return new ImportedFunction(functionName, functionOffset, functionOrdinal);
                    }
                }

                else
                {
                    var functionOffset = offsetTableOffset + sizeof(long) * functionIndex;

                    // Read the function thunk

                    var functionThunkOffset = thunkTableOffset + sizeof(long) * functionIndex;

                    var functionThunk = MemoryMarshal.Read<long>(ImageBytes.Span[functionThunkOffset..]);

                    if (functionThunk == 0)
                    {
                        break;
                    }

                    // Check if the function is imported via ordinal

                    if ((functionThunk & long.MinValue) != 0)
                    {
                        var functionOrdinal = functionThunk & ushort.MaxValue;

                        yield return new ImportedFunction(null, functionOffset, (int) functionOrdinal);
                    }

                    else
                    {
                        // Read the function ordinal

                        var functionOrdinalOffset = RvaToOffset((int) functionThunk);

                        var functionOrdinal = MemoryMarshal.Read<short>(ImageBytes.Span[functionOrdinalOffset..]);

                        // Read the function name

                        var functionNameOffset = functionOrdinalOffset + sizeof(short);

                        var functionNameLength = ImageBytes.Span[functionNameOffset..].IndexOf(byte.MinValue);

                        var functionName = Encoding.UTF8.GetString(ImageBytes.Span.Slice(functionNameOffset, functionNameLength));

                        yield return new ImportedFunction(functionName, functionOffset, functionOrdinal);
                    }
                }
            }
        }
    }
}