using System;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;

namespace Lunar.PortableExecutable
{
    internal abstract class DataDirectory
    {
        protected PEHeaders Headers { get; }

        private readonly Memory<byte> _imageBlock;

        protected DataDirectory(Memory<byte> imageBlock, PEHeaders headers)
        {
            _imageBlock = imageBlock;

            Headers = headers;
        }

        protected string ReadNullTerminatedString(int offset)
        {
            var stringLength = 0;

            while (_imageBlock.Span[offset + stringLength] != byte.MinValue)
            {
                stringLength += 1;
            }

            return Encoding.UTF8.GetString(_imageBlock.Slice(offset, stringLength).Span);
        }

        protected T ReadStructure<T>(int offset) where T : unmanaged
        {
            return MemoryMarshal.Read<T>(_imageBlock.Slice(offset).Span);
        }

        protected int RvaToOffset(int rva)
        {
            var sectionHeader = Headers.SectionHeaders[Headers.GetContainingSectionIndex(rva)];

            return rva - sectionHeader.VirtualAddress + sectionHeader.PointerToRawData;
        }

        protected int VaToRva(long va)
        {
            return (int) (va - (long) Headers.PEHeader.ImageBase);
        }
    }
}