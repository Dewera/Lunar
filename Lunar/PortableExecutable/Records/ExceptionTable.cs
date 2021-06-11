namespace Lunar.PortableExecutable.Records
{
    internal sealed record ExceptionTable(int HandlerCount, int RelativeAddress);
}