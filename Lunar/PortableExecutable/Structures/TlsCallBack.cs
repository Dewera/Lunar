namespace Lunar.PortableExecutable.Structures
{
    internal sealed class TlsCallBack
    {
        internal int Rva { get; }

        internal TlsCallBack(int rva)
        {
            Rva = rva;
        }
    }
}