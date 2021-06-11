using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal readonly struct ImageResourceDirectory
    {
        [FieldOffset(0xC)]
        internal readonly short NumberOfNameEntries;
        [FieldOffset(0xE)]
        internal readonly short NumberOfIdEntries;
    }
}