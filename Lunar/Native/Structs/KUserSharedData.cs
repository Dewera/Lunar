using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 1840)]
internal readonly record struct KUserSharedData([field: FieldOffset(0x330)] int Cookie);