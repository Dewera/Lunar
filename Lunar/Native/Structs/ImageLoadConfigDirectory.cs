using System.Runtime.InteropServices;
using Lunar.Native.Enums;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 172)]
    internal readonly struct ImageLoadConfigDirectory32
    {
        [FieldOffset(0x3C)]
        internal readonly int SecurityCookie;
        [FieldOffset(0x40)]
        internal readonly int SEHandlerTable;
        [FieldOffset(0x44)]
        internal readonly int SEHandlerCount;
        [FieldOffset(0x48)]
        private readonly int GuardCFCheckFunctionPointer;
        [FieldOffset(0x58)]
        internal readonly GuardFlags GuardFlags;
    }

    [StructLayout(LayoutKind.Explicit, Size = 280)]
    internal readonly struct ImageLoadConfigDirectory64
    {
        [FieldOffset(0x58)]
        internal readonly long SecurityCookie;
        [FieldOffset(0x70)]
        private readonly long GuardCFCheckFunctionPointer;
        [FieldOffset(0x78)]
        private readonly long GuardCFDispatchFunctionPointer;
        [FieldOffset(0x90)]
        internal readonly GuardFlags GuardFlags;
    }
}