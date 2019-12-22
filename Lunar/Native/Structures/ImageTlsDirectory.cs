using System.Runtime.InteropServices;

namespace Pluto.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal readonly struct ImageTlsDirectory32
    {
        [FieldOffset(0x0C)]
        internal readonly int AddressOfCallbacks;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal readonly struct ImageTlsDirectory64
    {
        [FieldOffset(0x18)]
        internal readonly long AddressOfCallbacks;
    }
}