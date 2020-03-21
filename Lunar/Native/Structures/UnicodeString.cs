using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal readonly struct UnicodeString32
    {
        [FieldOffset(0x00)]
        internal readonly short Length;

        [FieldOffset(0x04)]
        internal readonly int Buffer;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal readonly struct UnicodeString64
    {
        [FieldOffset(0x00)]
        internal readonly short Length;

        [FieldOffset(0x08)]
        internal readonly long Buffer;
    }
}