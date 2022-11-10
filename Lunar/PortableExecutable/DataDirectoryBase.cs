using System.Reflection.PortableExecutable;

namespace Lunar.PortableExecutable;

internal abstract class DataDirectoryBase
{
    protected private int DirectoryOffset { get; }
    protected private PEHeaders Headers { get; }
    protected private Memory<byte> ImageBytes { get; }
    protected private bool IsValid { get; }

    protected private DataDirectoryBase(DirectoryEntry directory, PEHeaders headers, Memory<byte> imageBytes)
    {
        headers.TryGetDirectoryOffset(directory, out var directoryOffset);

        DirectoryOffset = directoryOffset;
        Headers = headers;
        ImageBytes = imageBytes;
        IsValid = directoryOffset != -1;
    }

    protected private int RvaToOffset(int rva)
    {
        var sectionHeader = Headers.SectionHeaders[Headers.GetContainingSectionIndex(rva)];

        return rva - sectionHeader.VirtualAddress + sectionHeader.PointerToRawData;
    }

    protected private int VaToRva(int va)
    {
        return va - (int) Headers.PEHeader!.ImageBase;
    }

    protected private int VaToRva(long va)
    {
        return (int) (va - (long) Headers.PEHeader!.ImageBase);
    }
}