using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 48)]
    internal readonly struct PebLdrData32
    {
        [FieldOffset(0xC)]
        internal readonly ListEntry32 InLoadOrderModuleList;
    }

    [StructLayout(LayoutKind.Explicit, Size = 88)]
    internal readonly struct PebLdrData64
    {
        [FieldOffset(0x10)]
        internal readonly ListEntry64 InLoadOrderModuleList;
    }
}