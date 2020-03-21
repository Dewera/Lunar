using System;
using System.Collections.Generic;
using System.Collections.Immutable;
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
        internal ImmutableArray<BaseRelocation> BaseRelocations { get; }

        internal BaseRelocationDirectory(ReadOnlyMemory<byte> peBytes, PEHeaders peHeaders) : base(peBytes, peHeaders)
        {
            BaseRelocations = ReadBaseRelocations().ToImmutableArray();
        }
        
        private IEnumerable<BaseRelocation> ReadBaseRelocations()
        {
            // Calculate the offset of the first base relocation block
            
            if (!PeHeaders.TryGetDirectoryOffset(PeHeaders.PEHeader.BaseRelocationTableDirectory, out var currentRelocationBlockOffset))
            {
                yield break;
            }

            while (true)
            {
                // Read the current base relocation block

                var relocationBlock = MemoryMarshal.Read<ImageBaseRelocation>(PeBytes.Slice(currentRelocationBlockOffset).Span);

                if (relocationBlock.SizeOfBlock == 0)
                {
                    yield break;
                }
                
                // Read the base relocations from the base relocation block
                
                var relocationBlockSize = (relocationBlock.SizeOfBlock - Unsafe.SizeOf<ImageBaseRelocation>()) / sizeof(short);

                var relocationBlockOffset = RvaToOffset(relocationBlock.VirtualAddress);

                for (var relocationIndex = 0; relocationIndex < relocationBlockSize; relocationIndex ++)
                {
                    // Read the base relocation

                    var relocationOffset = currentRelocationBlockOffset + Unsafe.SizeOf<ImageBaseRelocation>() + sizeof(short) * relocationIndex;

                    var relocation = MemoryMarshal.Read<ushort>(PeBytes.Slice(relocationOffset).Span);
                    
                    // The offset is located in the upper 4 bits of the base relocation

                    var offset = relocation & 0xFFF;

                    // The type is located in the lower 12 bits of the base relocation

                    var type = relocation >> 12;
                    
                    yield return new BaseRelocation(relocationBlockOffset + offset, (BaseRelocationType) type);
                }
                
                // Calculate the offset of the next base relocation block

                currentRelocationBlockOffset += relocationBlock.SizeOfBlock;
            }
        }
    }
}