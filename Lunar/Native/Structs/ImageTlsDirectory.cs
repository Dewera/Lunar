using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 24)]
internal readonly record struct ImageTlsDirectory32([field: FieldOffset(0x8)] int AddressOfIndex, [field: FieldOffset(0xC)] int AddressOfCallBacks);

[StructLayout(LayoutKind.Explicit, Size = 40)]
internal readonly record struct ImageTlsDirectory64([field: FieldOffset(0x10)] long AddressOfIndex, [field: FieldOffset(0x18)] long AddressOfCallBacks);