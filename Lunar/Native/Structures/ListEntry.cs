using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal struct ListEntry32
    {
        [FieldOffset(0x0)]
        internal int Flink;

        [FieldOffset(0x4)]
        internal int Blink;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct ListEntry64
    {
        [FieldOffset(0x0)]
        internal long Flink;

        [FieldOffset(0x8)]
        internal long Blink;
    }
}