using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 8)]
internal struct ListEntry32
{
    [FieldOffset(0x0)]
    internal int Flink;
    [FieldOffset(0x4)]
    internal int Blink;

    internal ListEntry32(int flink, int blink)
    {
        Flink = flink;
        Blink = blink;
    }
}

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct ListEntry64
{
    [FieldOffset(0x0)]
    internal long Flink;
    [FieldOffset(0x8)]
    internal long Blink;

    internal ListEntry64(long flink, long blink)
    {
        Flink = flink;
        Blink = blink;
    }
}