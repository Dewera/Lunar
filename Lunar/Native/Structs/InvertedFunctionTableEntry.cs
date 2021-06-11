using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal readonly struct InvertedFunctionTableEntry32
    {
        [FieldOffset(0x0)]
        private readonly int ExceptionDirectory;
        [FieldOffset(0x4)]
        internal readonly int ImageBase;
        [FieldOffset(0x8)]
        private readonly int ImageSize;
        [FieldOffset(0xC)]
        private readonly int ExceptionDirectorySize;

        internal InvertedFunctionTableEntry32(int exceptionDirectory, int imageBase, int imageSize, int exceptionDirectorySize)
        {
            ExceptionDirectory = exceptionDirectory;
            ImageBase = imageBase;
            ImageSize = imageSize;
            ExceptionDirectorySize = exceptionDirectorySize;
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 24)]
    internal readonly struct InvertedFunctionTableEntry64
    {
        [FieldOffset(0x0)]
        private readonly long ExceptionDirectory;
        [FieldOffset(0x8)]
        internal readonly long ImageBase;
        [FieldOffset(0x10)]
        private readonly int ImageSize;
        [FieldOffset(0x14)]
        private readonly int ExceptionDirectorySize;

        internal InvertedFunctionTableEntry64(long exceptionDirectory, long imageBase, int imageSize, int exceptionDirectorySize)
        {
            ExceptionDirectory = exceptionDirectory;
            ImageBase = imageBase;
            ImageSize = imageSize;
            ExceptionDirectorySize = exceptionDirectorySize;
        }
    }
}