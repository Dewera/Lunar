using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 40)]
internal readonly record struct LdrpTlsEntry32([field: FieldOffset(0x0)] ListEntry32 EntryLinks, [field: FieldOffset(0x8)] ImageTlsDirectory32 TlsDirectory, [field: FieldOffset(0x24)] int Index);

[StructLayout(LayoutKind.Explicit, Size = 72)]
internal readonly record struct LdrpTlsEntry64([field: FieldOffset(0x0)] ListEntry64 EntryLinks, [field: FieldOffset(0x10)] ImageTlsDirectory64 TlsDirectory, [field: FieldOffset(0x40)] int Index);