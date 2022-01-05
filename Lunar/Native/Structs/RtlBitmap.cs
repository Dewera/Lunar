using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 8)]
internal readonly record struct RtlBitmap32([field: FieldOffset(0x0)] int SizeOfBitmap, [field: FieldOffset(0x4)] int Buffer);

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal readonly record struct RtlBitmap64([field: FieldOffset(0x0)] int SizeOfBitmap, [field: FieldOffset(0x8)] long Buffer);