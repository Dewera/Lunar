using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 8)]
internal readonly record struct ListEntry32([field: FieldOffset(0x0)] int Flink, [field: FieldOffset(0x4)] int Blink);

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal readonly record struct ListEntry64([field: FieldOffset(0x0)] long Flink, [field: FieldOffset(0x8)] long Blink);