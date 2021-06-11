using System;
using System.Collections.Immutable;
using System.Reflection.PortableExecutable;
using Lunar.PortableExecutable.DataDirectories;

namespace Lunar.PortableExecutable
{
    internal sealed class PeImage
    {
        internal ExportDirectory ExportDirectory { get; }
        internal PEHeaders Headers { get; }
        internal ImportDirectory ImportDirectory { get; }
        internal LoadConfigDirectory LoadConfigDirectory { get; }
        internal RelocationDirectory RelocationDirectory { get; }
        internal ResourceDirectory ResourceDirectory { get; }
        internal TlsDirectory TlsDirectory { get; }

        internal PeImage(Memory<byte> imageBytes)
        {
            using var peReader = new PEReader(imageBytes.ToArray().ToImmutableArray());

            if (peReader.PEHeaders.PEHeader is null || !peReader.PEHeaders.IsDll)
            {
                throw new BadImageFormatException("The provided file was not a valid DLL");
            }

            ExportDirectory = new ExportDirectory(peReader.PEHeaders, imageBytes);
            Headers = peReader.PEHeaders;
            ImportDirectory = new ImportDirectory(peReader.PEHeaders, imageBytes);
            LoadConfigDirectory = new LoadConfigDirectory(peReader.PEHeaders, imageBytes);
            RelocationDirectory = new RelocationDirectory(peReader.PEHeaders, imageBytes);
            ResourceDirectory = new ResourceDirectory(peReader.PEHeaders, imageBytes);
            TlsDirectory = new TlsDirectory(peReader.PEHeaders, imageBytes);
        }
    }
}