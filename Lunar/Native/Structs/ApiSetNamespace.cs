using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 28)]
internal readonly record struct ApiSetNamespace([field: FieldOffset(0xC)] int Count, [field: FieldOffset(0x10)] int EntryOffset, [field: FieldOffset(0x14)] int HashOffset, [field: FieldOffset(0x18)] int HashFactor);