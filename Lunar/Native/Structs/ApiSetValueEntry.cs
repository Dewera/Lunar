using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 20)]
    internal readonly struct ApiSetValueEntry
    {
        [FieldOffset(0xC)]
        internal readonly int ValueOffset;
        [FieldOffset(0x10)]
        internal readonly int ValueCount;
    }
}