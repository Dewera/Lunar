using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 20)]
internal readonly record struct ImageImportDescriptor([field: FieldOffset(0x0)] int OriginalFirstThunk, [field: FieldOffset(0xC)] int Name, [field: FieldOffset(0x10)] int FirstThunk);