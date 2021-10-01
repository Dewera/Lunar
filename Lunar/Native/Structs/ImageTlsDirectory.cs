using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 24)]
    internal readonly struct ImageTlsDirectory32
    {
        [FieldOffset(0x0)]
        internal readonly int StartAddressOfRawData;
        [FieldOffset(0x4)]
        internal readonly int EndAddressOfRawData;
        [FieldOffset(0x8)]
        internal readonly int AddressOfIndex;
        [FieldOffset(0xC)]
        internal readonly int AddressOfCallBacks;
    }

    [StructLayout(LayoutKind.Explicit, Size = 40)]
    internal readonly struct ImageTlsDirectory64
    {
        [FieldOffset(0x0)]
        internal readonly long StartAddressOfRawData;
        [FieldOffset(0x8)]
        internal readonly long EndAddressOfRawData;
        [FieldOffset(0x10)]
        internal readonly long AddressOfIndex;
        [FieldOffset(0x18)]
        internal readonly long AddressOfCallBacks;
    }
}