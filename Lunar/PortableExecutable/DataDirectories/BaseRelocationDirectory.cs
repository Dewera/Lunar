using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native.Enumerations;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal class BaseRelocationDirectory : DataDirectory
    {
        internal IEnumerable<BaseRelocation> BaseRelocations { get; }

        internal BaseRelocationDirectory(PEHeaders headers, Memory<byte> imageBlock) : base(headers, imageBlock)
        {
            BaseRelocations = ReadBaseRelocations();
        }

        private IEnumerable<BaseRelocation> ReadBaseRelocations()
        {
            if (!Headers.TryGetDirectoryOffset(Headers.PEHeader.BaseRelocationTableDirectory, out var currentRelocationBlockOffset))
            {
                yield break;
            }

            while (true)
            {
                // Read the base relocation block

                var relocationBlock = MemoryMarshal.Read<ImageBaseRelocation>(ImageBlock.Span.Slice(currentRelocationBlockOffset));

                if (relocationBlock.SizeOfBlock == 0)
                {
                    yield break;
                }

                var relocationBlockSize = (relocationBlock.SizeOfBlock - Unsafe.SizeOf<ImageBaseRelocation>()) / sizeof(short);

                var relocationBlockOffset = currentRelocationBlockOffset + Unsafe.SizeOf<ImageBaseRelocation>();

                for (var relocationIndex = 0; relocationIndex < relocationBlockSize; relocationIndex += 1)
                {
                    // Read the relocation

                    var relocationOffset = relocationBlockOffset + relocationIndex * sizeof(short);

                    var relocation = MemoryMarshal.Read<ushort>(ImageBlock.Span.Slice(relocationOffset));

                    // The offset is located in the lower 12 bits of the base relocation

                    var offset = RvaToOffset(relocationBlock.VirtualAddress) + (relocation & 0xFFF);

                    // The type is located in the upper 4 bits of the base relocation

                    var type = relocation >> 12;

                    yield return new BaseRelocation(offset, (BaseRelocationType) type);
                }

                currentRelocationBlockOffset += relocationBlock.SizeOfBlock;
            }
        }
    }
}