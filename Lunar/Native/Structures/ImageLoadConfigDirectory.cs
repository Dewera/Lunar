using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal readonly struct ImageLoadConfigDirectory32
    {
        [FieldOffset(0x3C)]
        internal readonly int SecurityCookie;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal readonly struct ImageLoadConfigDirectory64
    {
        [FieldOffset(0x58)]
        internal readonly long SecurityCookie;
    }
}