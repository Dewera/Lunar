using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 24)]
    internal readonly struct ImageTlsDirectory32
    {
        [FieldOffset(0xC)]
        internal readonly int AddressOfCallBacks;
    }

    [StructLayout(LayoutKind.Explicit, Size = 40)]
    internal readonly struct ImageTlsDirectory64
    {
        [FieldOffset(0x18)]
        internal readonly long AddressOfCallBacks;
    }
}