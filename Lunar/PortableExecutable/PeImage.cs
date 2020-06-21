using System;
using System.IO;
using System.Linq;
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

        internal CodeViewDebugDirectoryData PdbData { get; }

        internal TlsDirectory TlsDirectory { get; }

        internal PeImage(Memory<byte> imageBytes)
        {
            using var peReader = new PEReader(new MemoryStream(imageBytes.ToArray()));

            BaseRelocationDirectory = new BaseRelocationDirectory(peReader.PEHeaders, imageBytes);

            DelayImportDirectory = new DelayImportDirectory(peReader.PEHeaders, imageBytes);

            ExportDirectory = new ExportDirectory(peReader.PEHeaders, imageBytes);

            Headers = peReader.PEHeaders;

            ImportDirectory = new ImportDirectory(peReader.PEHeaders, imageBytes);

            LoadConfigDirectory = new LoadConfigDirectory(peReader.PEHeaders, imageBytes);

            var debugDirectoryEntries = peReader.ReadDebugDirectory();

            if (debugDirectoryEntries.Any(entry => entry.Type == DebugDirectoryEntryType.CodeView))
            {
                var codeViewEntry = debugDirectoryEntries.First(entry => entry.Type == DebugDirectoryEntryType.CodeView);

                PdbData = peReader.ReadCodeViewDebugDirectoryData(codeViewEntry);
            }

            TlsDirectory = new TlsDirectory(peReader.PEHeaders, imageBytes);

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