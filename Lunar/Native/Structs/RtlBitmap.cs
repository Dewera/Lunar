using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 8)]
internal struct RtlBitmap32
{
    [FieldOffset(0x0)]
    internal int SizeOfBitmap;
    [FieldOffset(0x4)]
    internal int Buffer;
}

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct RtlBitmap64
{
    [FieldOffset(0x0)]
    internal int SizeOfBitmap;
    [FieldOffset(0x8)]
    internal long Buffer;
}