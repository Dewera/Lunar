using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 192)]
internal readonly record struct LdrDataTableEntry32([field: FieldOffset(0x18)] int DllBase);

[StructLayout(LayoutKind.Explicit, Size = 312)]
internal readonly record struct LdrDataTableEntry64([field: FieldOffset(0x30)] long DllBase);