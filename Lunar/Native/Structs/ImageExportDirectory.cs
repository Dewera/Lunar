using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 40)]
internal readonly record struct ImageExportDirectory([field: FieldOffset(0x10)] int Base, [field: FieldOffset(0x14)] int NumberOfFunctions, [field: FieldOffset(0x18)] int NumberOfNames, [field: FieldOffset(0x1C)] int AddressOfFunctions, [field: FieldOffset(0x20)] int AddressOfNames, [field: FieldOffset(0x24)] int AddressOfNameOrdinals);