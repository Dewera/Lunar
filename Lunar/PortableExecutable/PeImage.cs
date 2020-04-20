using System;
using System.Collections.Immutable;
using System.Linq;
using System.Reflection.PortableExecutable;
using Lunar.PortableExecutable.DataDirectories;

namespace Lunar.PortableExecutable
{
    internal sealed class PeImage
    {
        internal Lazy<BaseRelocationDirectory> BaseRelocationDirectory { get; }

        internal CodeViewDebugDirectoryData CodeViewDebugDirectoryData { get; }

        internal Lazy<DelayImportDirectory> DelayImportDirectory { get; }

        internal Lazy<ExportDirectory> ExportDirectory { get; }

        internal Lazy<ImportDirectory> ImportDirectory { get; }

        internal Lazy<LoadConfigDirectory> LoadConfigDirectory { get; }

        internal PEHeaders PeHeaders { get; }

        internal Lazy<TlsDirectory> TlsDirectory { get; }

        internal PeImage(ReadOnlyMemory<byte> peBytes)
        {
            using var peReader = new PEReader(peBytes.ToArray().ToImmutableArray());

            ValidatePeImage(peReader.PEHeaders);

            BaseRelocationDirectory = new Lazy<BaseRelocationDirectory>(() => new BaseRelocationDirectory(peBytes, PeHeaders));

            CodeViewDebugDirectoryData = ReadCodeViewDebugDirectoryData(peReader);

            DelayImportDirectory = new Lazy<DelayImportDirectory>(() => new DelayImportDirectory(peBytes, PeHeaders));

            ExportDirectory = new Lazy<ExportDirectory>(() => new ExportDirectory(peBytes, PeHeaders));

            ImportDirectory = new Lazy<ImportDirectory>(() => new ImportDirectory(peBytes, PeHeaders));

            LoadConfigDirectory = new Lazy<LoadConfigDirectory>(() => new LoadConfigDirectory(peBytes, PeHeaders));

            PeHeaders = peReader.PEHeaders;

            TlsDirectory = new Lazy<TlsDirectory>(() => new TlsDirectory(peBytes, PeHeaders));
        }

        private static CodeViewDebugDirectoryData ReadCodeViewDebugDirectoryData(PEReader peReader)
        {
            // Look for the first code view entry in the debug directory entries

            var debugDirectoryEntries = peReader.ReadDebugDirectory();

            var codeViewEntry = debugDirectoryEntries.FirstOrDefault(entry => entry.Type == DebugDirectoryEntryType.CodeView);

            return codeViewEntry.Equals(default(DebugDirectoryEntry)) ? default : peReader.ReadCodeViewDebugDirectoryData(codeViewEntry);
        }

        private static void ValidatePeImage(PEHeaders peHeaders)
        {
            if (!peHeaders.IsDll)
            {
                throw new BadImageFormatException("The provided file was not a valid DLL");
            }

            if (peHeaders.CorHeader != null)
            {
                throw new BadImageFormatException("The provided file was a managed DLL and cannot be mapped");
            }
        }
    }
}