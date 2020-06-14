using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 24)]
    internal readonly struct ApiSetNamespaceEntry
    {
        [FieldOffset(0x10)]
        internal readonly int ValueOffset;
    }
}