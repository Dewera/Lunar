namespace Lunar.PortableExecutable.Structures
{
    internal sealed class SecurityCookie
    {
        internal int Offset { get; }

        internal SecurityCookie(int offset)
        {
            Offset = offset;
        }
    }
}