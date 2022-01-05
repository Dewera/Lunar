using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Lunar.Native;
using Lunar.Native.Structs;

namespace Lunar.PortableExecutable.DataDirectories;

internal sealed class ResourceDirectory : DataDirectoryBase
{
    internal ResourceDirectory(PEHeaders headers, Memory<byte> imageBytes) : base(headers.PEHeader!.ResourceTableDirectory, headers, imageBytes) { }

    internal XDocument? GetManifest()
    {
        if (!IsValid)
        {
            return null;
        }

        // Read the resource directory

        var resourceDirectory = MemoryMarshal.Read<ImageResourceDirectory>(ImageBytes.Span[DirectoryOffset..]);
        var resourceCount = resourceDirectory.NumberOfIdEntries + resourceDirectory.NumberOfNameEntries;

        for (var resourceIndex = 0; resourceIndex < resourceCount; resourceIndex += 1)
        {
            // Read the first level resource entry

            var firstLevelResourceEntryOffset = DirectoryOffset + Unsafe.SizeOf<ImageResourceDirectory>() + Unsafe.SizeOf<ImageResourceDirectoryEntry>() * resourceIndex;
            var firstLevelResourceEntry = MemoryMarshal.Read<ImageResourceDirectoryEntry>(ImageBytes.Span[firstLevelResourceEntryOffset..]);

            if (firstLevelResourceEntry.Id != Constants.ManifestResourceId)
            {
                continue;
            }

            // Read the second level resource entry

            var secondLevelResourceEntryOffset = DirectoryOffset + Unsafe.SizeOf<ImageResourceDirectory>() + (firstLevelResourceEntry.OffsetToData & int.MaxValue);
            var secondLevelResourceEntry = MemoryMarshal.Read<ImageResourceDirectoryEntry>(ImageBytes.Span[secondLevelResourceEntryOffset..]);

            if (secondLevelResourceEntry.Id != Constants.DllManifestId)
            {
                continue;
            }

            // Read the third level resource entry

            var thirdLevelResourceEntryOffset = DirectoryOffset + Unsafe.SizeOf<ImageResourceDirectory>() + (secondLevelResourceEntry.OffsetToData & int.MaxValue);
            var thirdLevelResourceEntry = MemoryMarshal.Read<ImageResourceDirectoryEntry>(ImageBytes.Span[thirdLevelResourceEntryOffset..]);

            // Read the manifest entry

            var manifestEntryOffset = DirectoryOffset + thirdLevelResourceEntry.OffsetToData;
            var manifestEntry = MemoryMarshal.Read<ImageResourceDataEntry>(ImageBytes.Span[manifestEntryOffset..]);

            // Read the manifest

            var manifestOffset = RvaToOffset(manifestEntry.OffsetToData);
            var manifest = Encoding.UTF8.GetString(ImageBytes.Span.Slice(manifestOffset, manifestEntry.Size));

            // Sanitise the manifest to ensure it can be parsed correctly

            manifest = Regex.Replace(manifest, @"\""\""([\d\w\.]*)\""\""", @"""$1""");
            manifest = Regex.Replace(manifest, @"^\s+$[\r\n]*", string.Empty, RegexOptions.Multiline);
            manifest = manifest.Replace("SXS_ASSEMBLY_NAME", @"""""");
            manifest = manifest.Replace("SXS_ASSEMBLY_VERSION", @"""""");
            manifest = manifest.Replace("SXS_PROCESSOR_ARCHITECTURE", @"""""");

            return XDocument.Parse(manifest);
        }

        return null;
    }
}