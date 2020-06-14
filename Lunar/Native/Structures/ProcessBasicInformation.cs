using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 24)]
    internal readonly struct ProcessBasicInformation32
    {
        [FieldOffset(0x4)]
        internal readonly int PebBaseAddress;
    }

    [StructLayout(LayoutKind.Explicit, Size = 48)]
    internal readonly struct ProcessBasicInformation64
    {
        [FieldOffset(0x8)]
        internal readonly long PebBaseAddress;
    }
}