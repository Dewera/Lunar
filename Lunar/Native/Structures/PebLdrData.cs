using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 48)]
    internal struct PebLdrData32
    {
        [FieldOffset(0x14)]
        internal ListEntry32 InLoadOrderModuleList;

        [FieldOffset(0x14)]
        internal ListEntry32 InMemoryOrderModuleList;

        [FieldOffset(0x14)]
        internal ListEntry32 InInitializationOrderModuleList;
    }

    [StructLayout(LayoutKind.Explicit, Size = 88)]
    internal struct PebLdrData64
    {
        [FieldOffset(0x10)]
        internal ListEntry64 InLoadOrderModuleList;

        [FieldOffset(0x20)]
        internal ListEntry64 InMemoryOrderModuleList;

        [FieldOffset(0x30)]
        internal ListEntry64 InInitializationOrderModuleList;
    }
}