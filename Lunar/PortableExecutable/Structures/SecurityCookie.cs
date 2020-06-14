namespace Lunar.PortableExecutable.Structures
{
    internal sealed class SecurityCookie
    {
        internal int Rva { get; }

        internal SecurityCookie(int rva)
        {
            Rva = rva;
        }
    }
}