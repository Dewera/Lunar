using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 1808)]
    internal readonly struct KUserSharedData
    {
        [FieldOffset(0x330)]
        internal readonly int Cookie;
    }
}