using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 1152)]
    internal readonly struct Peb32
    {
        [FieldOffset(0xC)]
        internal readonly int Ldr;

        [FieldOffset(0x38)]
        internal readonly int ApiSetMap;
    }

    [StructLayout(LayoutKind.Explicit, Size = 1992)]
    internal readonly struct Peb64
    {
        [FieldOffset(0x18)]
        internal readonly long Ldr;

        [FieldOffset(0x68)]
        internal readonly long ApiSetMap;
    }
}