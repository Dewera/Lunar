using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 24)]
internal readonly record struct ApiSetNamespaceEntry([field: FieldOffset(0x10)] int ValueOffset);