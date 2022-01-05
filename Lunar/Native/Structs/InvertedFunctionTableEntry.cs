using System.Runtime.InteropServices;

namespace Lunar.Native.Structs;

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal readonly struct InvertedFunctionTableEntry32
{
    [FieldOffset(0x0)]
    private readonly int FunctionTable;
    [FieldOffset(0x4)]
    internal readonly int ImageBase;
    [FieldOffset(0x8)]
    private readonly int SizeOfImage;
    [FieldOffset(0xC)]
    private readonly int SizeOfTable;

    internal InvertedFunctionTableEntry32(int functionTable, int imageBase, int sizeOfImage, int sizeOfTable)
    {
        FunctionTable = functionTable;
        ImageBase = imageBase;
        SizeOfImage = sizeOfImage;
        SizeOfTable = sizeOfTable;
    }
}

[StructLayout(LayoutKind.Explicit, Size = 24)]
internal readonly struct InvertedFunctionTableEntry64
{
    [FieldOffset(0x0)]
    private readonly long FunctionTable;
    [FieldOffset(0x8)]
    internal readonly long ImageBase;
    [FieldOffset(0x10)]
    private readonly int SizeOfImage;
    [FieldOffset(0x14)]
    private readonly int SizeOfTable;

    internal InvertedFunctionTableEntry64(long functionTable, long imageBase, int sizeOfImage, int sizeOfTable)
    {
        FunctionTable = functionTable;
        ImageBase = imageBase;
        SizeOfImage = sizeOfImage;
        SizeOfTable = sizeOfTable;
    }
}