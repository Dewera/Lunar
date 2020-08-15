using System;
using System.IO;
using System.Reflection.PortableExecutable;
using Lunar.PortableExecutable.DataDirectories;

namespace Lunar.PortableExecutable
{
    internal sealed class PeImage
    {
        internal BaseRelocationDirectory BaseRelocationDirectory { get; }

        internal DelayImportDirectory DelayImportDirectory { get; }

        internal ExportDirectory ExportDirectory { get; }

        internal PEHeaders Headers { get; }

        internal ImportDirectory ImportDirectory { get; }

        internal LoadConfigDirectory LoadConfigDirectory { get; }

        internal TlsDirectory TlsDirectory { get; }

        internal PeImage(Memory<byte> imageBuffer)
        {
            using var peReader = new PEReader(new MemoryStream(imageBuffer.ToArray()));

            BaseRelocationDirectory = new BaseRelocationDirectory(peReader.PEHeaders, imageBuffer);

            DelayImportDirectory = new DelayImportDirectory(peReader.PEHeaders, imageBuffer);

            ExportDirectory = new ExportDirectory(peReader.PEHeaders, imageBuffer);

            Headers = peReader.PEHeaders;

            ImportDirectory = new ImportDirectory(peReader.PEHeaders, imageBuffer);

            LoadConfigDirectory = new LoadConfigDirectory(peReader.PEHeaders, imageBuffer);

            TlsDirectory = new TlsDirectory(peReader.PEHeaders, imageBuffer);

            ValidatePeImage();
        }

        private void ValidatePeImage()
        {
            if (!Headers.IsDll)
            {
                throw new BadImageFormatException("The provided file was not a valid DLL");
            }

            if (Headers.CorHeader != null)
            {
                throw new BadImageFormatException("The provided file was a managed DLL and cannot be mapped");
            }
        }
    }
}