namespace Lunar.PortableExecutable.Structures
{
    internal sealed record ExportedFunction(string? ForwarderString, int RelativeAddress);
}