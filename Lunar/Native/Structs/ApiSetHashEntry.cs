using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal readonly struct ApiSetHashEntry
    {
        [FieldOffset(0x0)]
        internal readonly int Hash;
        [FieldOffset(0x4)]
        internal readonly int Index;
    }
}