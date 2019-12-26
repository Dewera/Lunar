namespace Lunar.PortableExecutable.Structures
{
    internal sealed class SecurityCookie
    {
        internal int Offset { get; }

        internal byte[] Value { get; }

        internal SecurityCookie(int offset, byte[] value)
        {
            Offset = offset;

            Value = value;
        }
    }
}