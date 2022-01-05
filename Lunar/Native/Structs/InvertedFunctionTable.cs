using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct InvertedFunctionTable
{
    [FieldOffset(0x0)]
    internal int CurrentSize;
    [FieldOffset(0x4)]
    internal readonly int MaximumSize;
    [FieldOffset(0xC)]
    internal bool Overflow;
}