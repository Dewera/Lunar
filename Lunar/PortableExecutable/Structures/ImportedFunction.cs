namespace Lunar.PortableExecutable.Structures
{
    internal sealed record ImportedFunction(string? Name, int Offset, int Ordinal);
}