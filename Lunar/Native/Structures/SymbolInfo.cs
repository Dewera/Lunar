using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 88)]
    internal readonly struct SymbolInfo
    {
        [FieldOffset(0x0)]
        private readonly int SizeOfStruct;

        [FieldOffset(0x38)]
        internal readonly long Address;

        [FieldOffset(0x50)]
        private readonly int MaxNameLen;

        internal SymbolInfo(int nameBufferSize)
        {
            SizeOfStruct = Unsafe.SizeOf<SymbolInfo>();

            Address = 0;

            MaxNameLen = nameBufferSize;
        }
    }
}