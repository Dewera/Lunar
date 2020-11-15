using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 168)]
    internal readonly struct LdrDataTableEntry32
    {
        [FieldOffset(0x0)]
        internal readonly ListEntry32 InLoadOrderLinks;

        [FieldOffset(0x18)]
        internal readonly int DllBase;

        [FieldOffset(0x24)]
        internal readonly UnicodeString32 FullDllName;

        [FieldOffset(0x2C)]
        internal readonly UnicodeString32 BaseDllName;
    }

    [StructLayout(LayoutKind.Explicit, Size = 288)]
    internal readonly struct LdrDataTableEntry64
    {
        [FieldOffset(0x0)]
        internal readonly ListEntry64 InLoadOrderLinks;

        [FieldOffset(0x30)]
        internal readonly long DllBase;

        [FieldOffset(0x48)]
        internal readonly UnicodeString64 FullDllName;

        [FieldOffset(0x58)]
        internal readonly UnicodeString64 BaseDllName;
    }
}