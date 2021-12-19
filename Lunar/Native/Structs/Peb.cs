using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 1160)]
internal readonly struct Peb32
{
    [FieldOffset(0x18)]
    internal readonly int ProcessHeap;
    [FieldOffset(0x38)]
    internal readonly int ApiSetMap;
}

[StructLayout(LayoutKind.Explicit, Size = 2000)]
internal readonly struct Peb64
{
    [FieldOffset(0x30)]
    internal readonly long ProcessHeap;
    [FieldOffset(0x68)]
    internal readonly long ApiSetMap;
}