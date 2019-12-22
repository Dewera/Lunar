namespace Pluto.PortableExecutable.Structures
{
    internal sealed class TlsCallback
    {
        internal int Offset { get; }

        internal TlsCallback(int offset)
        {
            Offset = offset;
        }
    }
}