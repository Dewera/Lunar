using System.Runtime.InteropServices;
using Lunar.Native.Enums;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 172)]
internal readonly record struct ImageLoadConfigDirectory32([field: FieldOffset(0x3C)] int SecurityCookie, [field: FieldOffset(0x40)] int SEHandlerTable, [field: FieldOffset(0x44)] int SEHandlerCount, [field: FieldOffset(0x48)] int GuardCFCheckFunctionPointer, [field: FieldOffset(0x58)] GuardFlags GuardFlags);

[StructLayout(LayoutKind.Explicit, Size = 280)]
internal readonly record struct ImageLoadConfigDirectory64([field: FieldOffset(0x58)] long SecurityCookie, [field: FieldOffset(0x70)] long GuardCFCheckFunctionPointer, [field: FieldOffset(0x78)] long GuardCFDispatchFunctionPointer, [field: FieldOffset(0x90)] GuardFlags GuardFlags);