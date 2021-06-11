namespace Lunar.PortableExecutable.Records
{
    internal sealed record ImportedFunction(string? Name, int Offset, int Ordinal);
}