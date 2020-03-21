using System.Runtime.InteropServices;

namespace Lunar.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct ListEntry32
    {
        internal readonly int Flink;

        internal readonly int Blink;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct ListEntry64
    {
        internal readonly long Flink;

        internal readonly long Blink;
    }
}