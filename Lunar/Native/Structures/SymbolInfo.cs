using System.Runtime.InteropServices;

namespace Pluto.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 88)]
    internal struct SymbolInfo
    {
        [FieldOffset(0x00)]
        internal int SizeOfStruct;

        [FieldOffset(0x38)]
        internal readonly long Address;

        [FieldOffset(0x50)]
        internal int MaxNameLen;
    }
}