using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal struct UnicodeString32
    {
        [FieldOffset(0x0)]
        internal short Length;

        [FieldOffset(0x2)]
        internal short MaximumLength;

        [FieldOffset(0x4)]
        internal int Buffer;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct UnicodeString64
    {
        [FieldOffset(0x0)]
        internal short Length;

        [FieldOffset(0x2)]
        internal short MaximumLength;

        [FieldOffset(0x8)]
        internal long Buffer;
    }
}