using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 20)]
internal readonly record struct ApiSetValueEntry([field: FieldOffset(0x4)] int NameOffset, [field: FieldOffset(0x8)] int NameLength, [field: FieldOffset(0xC)] int ValueOffset, [field: FieldOffset(0x10)] int ValueCount);