using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 88)]
    internal struct SymbolInfo
    {
        [FieldOffset(0x0)]
        internal int SizeOfStruct;

        [FieldOffset(0x38)]
        internal long Address;

        [FieldOffset(0x50)]
        internal int MaxNameLen;
    }
}