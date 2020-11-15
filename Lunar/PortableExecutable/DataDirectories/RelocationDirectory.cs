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
    internal sealed class RelocationDirectory : DataDirectory
    {
        internal RelocationDirectory(PEHeaders headers, Memory<byte> imageBytes) : base(headers, imageBytes, headers.PEHeader!.BaseRelocationTableDirectory) { }

        internal IEnumerable<Relocation> GetRelocations()
        {
            if (!IsValid)
            {
                yield break;
            }

            var currentRelocationBlockOffset = DirectoryOffset;

            while (true)
            {
                // Read the relocation block

                var relocationBlock = MemoryMarshal.Read<ImageBaseRelocation>(ImageBytes.Span.Slice(currentRelocationBlockOffset));

                if (relocationBlock.SizeOfBlock == 0)
                {
                    break;
                }

                var relocationCount = (relocationBlock.SizeOfBlock - Unsafe.SizeOf<ImageBaseRelocation>()) / sizeof(short);

                for (var relocationIndex = 0; relocationIndex < relocationCount; relocationIndex += 1)
                {
                    // Read the relocation

                    var relocationOffset = currentRelocationBlockOffset + Unsafe.SizeOf<ImageBaseRelocation>() + sizeof(short) * relocationIndex;

                    var relocation = MemoryMarshal.Read<short>(ImageBytes.Span.Slice(relocationOffset));

                    // The type is located in the upper 4 bits of the relocation

                    var type = (ushort) relocation >> 12;

                    // The offset if located in the lower 12 bits of the relocation

                    var offset = relocation & 0xFFF;

                    yield return new Relocation(RvaToOffset(relocationBlock.VirtualAddress) + offset, (RelocationType) type);
                }

                currentRelocationBlockOffset += relocationBlock.SizeOfBlock;
            }
        }
    }
}