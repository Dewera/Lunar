using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 48)]
internal readonly record struct ProcessBasicInformation64([field: FieldOffset(0x8)] long PebBaseAddress);