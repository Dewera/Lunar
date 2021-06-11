namespace Lunar.PortableExecutable.Records
{
    internal sealed record ExportedFunction(string? ForwarderString, int RelativeAddress);
}