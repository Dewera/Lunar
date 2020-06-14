using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 48)]
    internal readonly struct PebLdrData32
    {
        [FieldOffset(0x14)]
        internal readonly ListEntry32 InMemoryOrderModuleList;
    }

    [StructLayout(LayoutKind.Explicit, Size = 88)]
    internal readonly struct PebLdrData64
    {
        [FieldOffset(0x20)]
        internal readonly ListEntry64 InMemoryOrderModuleList;
    }
}