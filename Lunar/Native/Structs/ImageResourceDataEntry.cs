using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal readonly struct ImageResourceDataEntry
    {
        [FieldOffset(0x0)]
        internal readonly int OffsetToData;
        [FieldOffset(0x4)]
        internal readonly int Size;
    }
}