using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal readonly struct ImageBaseRelocation
    {
        [FieldOffset(0x0)]
        internal readonly int VirtualAddress;

        [FieldOffset(0x4)]
        internal readonly int SizeOfBlock;
    }
}