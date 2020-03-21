using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal readonly struct PebLdrData32
    {
        [FieldOffset(0x14)]
        internal readonly ListEntry32 InMemoryOrderModuleList;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal readonly struct PebLdrData64
    {
        [FieldOffset(0x20)]
        internal readonly ListEntry64 InMemoryOrderModuleList;
    }
}