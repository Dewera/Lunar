namespace Lunar.PortableExecutable.Structures
{
    internal sealed record ExceptionTable(int HandlerCount, int RelativeAddress);
}