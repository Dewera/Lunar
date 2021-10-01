using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal readonly struct ListEntry32
    {
        [FieldOffset(0x0)]
        internal readonly int Flink;
        [FieldOffset(0x4)]
        internal readonly int Blink;

        internal ListEntry32(int flink, int blink)
        {
            Flink = flink;
            Blink = blink;
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal readonly struct ListEntry64
    {
        [FieldOffset(0x0)]
        internal readonly long Flink;
        [FieldOffset(0x8)]
        internal readonly long Blink;

        internal ListEntry64(long flink, long blink)
        {
            Flink = flink;
            Blink = blink;
        }
    }
}