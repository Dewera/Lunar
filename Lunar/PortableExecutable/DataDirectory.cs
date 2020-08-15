using System;
using System.Reflection.PortableExecutable;
using System.Text;

namespace Lunar.PortableExecutable
{
    internal abstract class DataDirectory
    {
        protected PEHeaders Headers { get; }

        protected Memory<byte> ImageBuffer { get; }

        protected DataDirectory(PEHeaders headers, Memory<byte> imageBuffer)
        {
            Headers = headers;

            ImageBuffer = imageBuffer;
        }

        protected string ReadString(int offset)
        {
            var stringLength = 0;

            while (ImageBuffer.Span[offset + stringLength] != byte.MinValue)
            {
                stringLength += 1;
            }

            return Encoding.UTF8.GetString(ImageBuffer.Span.Slice(offset, stringLength));
        }

        protected int RvaToOffset(int rva)
        {
            var sectionHeader = Headers.SectionHeaders[Headers.GetContainingSectionIndex(rva)];

            return rva - sectionHeader.VirtualAddress + sectionHeader.PointerToRawData;
        }

        protected int VaToRva(int va)
        {
            return va - (int) Headers.PEHeader.ImageBase;
        }

        protected int VaToRva(long va)
        {
            return (int) (va - (long) Headers.PEHeader.ImageBase);
        }
    }
}