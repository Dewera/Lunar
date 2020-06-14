using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal readonly struct UnicodeString32
    {
        [FieldOffset(0x0)]
        internal readonly short Length;

        [FieldOffset(0x4)]
        internal readonly int Buffer;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal readonly struct UnicodeString64
    {
        [FieldOffset(0x0)]
        internal readonly short Length;

        [FieldOffset(0x8)]
        internal readonly long Buffer;
    }
}