using System;
using System.Reflection.PortableExecutable;
using System.Text;

namespace Lunar.PortableExecutable
{
    internal abstract class DataDirectory
    {
        protected ReadOnlyMemory<byte> PeBytes { get; }
        
        protected PEHeaders PeHeaders { get; }

        protected DataDirectory(ReadOnlyMemory<byte> peBytes, PEHeaders peHeaders)
        {
            PeBytes = peBytes;

            PeHeaders = peHeaders;
        }

        protected string ReadNullTerminatedString(int offset)
        {
            var stringLength = 0;

            while (PeBytes.Span[offset + stringLength] != byte.MinValue)
            {
                stringLength += 1;
            }

            return Encoding.UTF8.GetString(PeBytes.Slice(offset, stringLength).Span);
        }
        
        protected int RvaToOffset(int rva)
        {
            var sectionHeader = PeHeaders.SectionHeaders[PeHeaders.GetContainingSectionIndex(rva)];

            return rva - sectionHeader.VirtualAddress + sectionHeader.PointerToRawData;
        }
    }
}