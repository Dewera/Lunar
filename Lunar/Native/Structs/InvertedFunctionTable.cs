using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal readonly struct InvertedFunctionTable
    {
        [FieldOffset(0x0)]
        internal readonly int Count;
        [FieldOffset(0x4)]
        internal readonly int MaxCount;
        [FieldOffset(0xC)]
        internal readonly int Overflow;

        internal InvertedFunctionTable(int count, int maxCount, int overflow)
        {
            Count = count;
            MaxCount = maxCount;
            Overflow = overflow;
        }
    }
}