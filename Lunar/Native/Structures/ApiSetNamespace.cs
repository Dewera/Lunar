using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 28)]
    internal readonly struct ApiSetNamespace
    {
        [FieldOffset(0xC)]
        internal readonly int Count;

        [FieldOffset(0x10)]
        internal readonly int EntryOffset;

        [FieldOffset(0x14)]
        internal readonly int HashOffset;

        [FieldOffset(0x18)]
        internal readonly int HashFactor;
    }
}