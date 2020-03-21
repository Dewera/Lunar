using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 32)]
    internal readonly struct ImageDelayLoadDescriptor
    {
        [FieldOffset(0x04)]
        internal readonly int DllNameRva;

        [FieldOffset(0x0C)]
        internal readonly int ImportAddressTableRva;

        [FieldOffset(0x10)]
        internal readonly int ImportNameTableRva;
    }
}