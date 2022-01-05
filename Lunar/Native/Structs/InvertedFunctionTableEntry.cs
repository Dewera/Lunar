using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal readonly record struct InvertedFunctionTableEntry32([field: FieldOffset(0x0)] int FunctionTable, [field: FieldOffset(0x4)] int ImageBase, [field: FieldOffset(0x8)] int SizeOfImage, [field: FieldOffset(0xC)] int SizeOfTable);

[StructLayout(LayoutKind.Explicit, Size = 24)]
internal readonly record struct InvertedFunctionTableEntry64([field: FieldOffset(0x0)] long FunctionTable, [field: FieldOffset(0x8)] long ImageBase, [field: FieldOffset(0x10)] int SizeOfImage, [field: FieldOffset(0x14)] int SizeOfTable);