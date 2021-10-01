using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 48)]
    internal readonly struct ThreadBasicInformation64
    {
        [FieldOffset(0x8)]
        internal readonly long TebBaseAddress;
    }
}