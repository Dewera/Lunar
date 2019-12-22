using System.Runtime.InteropServices;

namespace Pluto.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal readonly struct ApiSetValueEntry
    {
        [FieldOffset(0x0C)]
        internal readonly int ValueOffset;

        [FieldOffset(0x10)]
        internal readonly int ValueCount;
    }
}