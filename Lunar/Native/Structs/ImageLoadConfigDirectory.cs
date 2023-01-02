using System.Runtime.InteropServices;
using Lunar.Native.Enums;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 172)]
internal readonly record struct ImageLoadConfigDirectory32([field: FieldOffset(0x3C)] int SecurityCookie, [field: FieldOffset(0x40)] int SeHandlerTable, [field: FieldOffset(0x44)] int SeHandlerCount, [field: FieldOffset(0x48)] int GuardCfCheckFunctionPointer, [field: FieldOffset(0x58)] GuardFlags GuardFlags);

[StructLayout(LayoutKind.Explicit, Size = 280)]
internal readonly record struct ImageLoadConfigDirectory64([field: FieldOffset(0x58)] long SecurityCookie, [field: FieldOffset(0x70)] long GuardCfCheckFunctionPointer, [field: FieldOffset(0x78)] long GuardCfDispatchFunctionPointer, [field: FieldOffset(0x90)] GuardFlags GuardFlags);