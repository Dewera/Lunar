using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal readonly struct RtlBitmap32
    {
        [FieldOffset(0x0)]
        internal readonly int SizeOfBitmap;
        [FieldOffset(0x4)]
        internal readonly int Buffer;

        internal RtlBitmap32(int sizeOfBitmap, int buffer)
        {
            SizeOfBitmap = sizeOfBitmap;
            Buffer = buffer;
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal readonly struct RtlBitmap64
    {
        [FieldOffset(0x0)]
        internal readonly int SizeOfBitmap;
        [FieldOffset(0x8)]
        internal readonly long Buffer;

        internal RtlBitmap64(int sizeOfBitmap, long buffer)
        {
            SizeOfBitmap = sizeOfBitmap;
            Buffer = buffer;
        }
    }
}