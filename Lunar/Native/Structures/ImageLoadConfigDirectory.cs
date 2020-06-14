using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 164)]
    internal readonly struct ImageLoadConfigDirectory32
    {
        [FieldOffset(0x3C)]
        internal readonly int SecurityCookie;

        [FieldOffset(0x40)]
        internal readonly int SEHandlerTable;

        [FieldOffset(0x44)]
        internal readonly int SEHandlerCount;
    }

    [StructLayout(LayoutKind.Explicit, Size = 264)]
    internal readonly struct ImageLoadConfigDirectory64
    {
        [FieldOffset(0x58)]
        internal readonly long SecurityCookie;
    }
}