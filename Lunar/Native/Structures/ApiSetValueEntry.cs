using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 20)]
    internal readonly struct ApiSetValueEntry
    {
        [FieldOffset(0x0C)]
        internal readonly int ValueOffset;

        [FieldOffset(0x10)]
        internal readonly int ValueCount;
    }
}