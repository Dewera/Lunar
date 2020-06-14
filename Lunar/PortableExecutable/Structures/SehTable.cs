namespace Lunar.PortableExecutable.Structures
{
    internal sealed class SehTable
    {
        internal int HandlerCount { get; }

        internal int Rva { get; }

        internal SehTable(int handlerCount, int rva)
        {
            HandlerCount = handlerCount;

            Rva = rva;
        }
    }
}