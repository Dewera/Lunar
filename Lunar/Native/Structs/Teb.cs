using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 4096)]
    internal readonly struct Teb32
    {
        [FieldOffset(0x2C)]
        internal readonly int ThreadLocalStoragePointer;
    }

    [StructLayout(LayoutKind.Explicit, Size = 6200)]
    internal readonly struct Teb64
    {
        [FieldOffset(0x58)]
        internal readonly long ThreadLocalStoragePointer;
        [FieldOffset(0x180C)]
        internal readonly int WowTebOffset;
    }
}