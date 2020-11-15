using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 20)]
    internal readonly struct ImageImportDescriptor
    {
        [FieldOffset(0x0)]
        internal readonly int OriginalFirstThunk;

        [FieldOffset(0xC)]
        internal readonly int Name;

        [FieldOffset(0x10)]
        internal readonly int FirstThunk;
    }
}