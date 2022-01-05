using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 88)]
internal readonly record struct SymbolInfo([field: FieldOffset(0x0)] int SizeOfStruct, [field: FieldOffset(0x38)] long Address, [field: FieldOffset(0x50)] int MaxNameLen);