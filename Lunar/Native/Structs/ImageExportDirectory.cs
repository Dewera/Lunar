using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 40)]
    internal readonly struct ImageExportDirectory
    {
        [FieldOffset(0x10)]
        internal readonly int Base;
        [FieldOffset(0x14)]
        internal readonly int NumberOfFunctions;
        [FieldOffset(0x18)]
        internal readonly int NumberOfNames;
        [FieldOffset(0x1C)]
        internal readonly int AddressOfFunctions;
        [FieldOffset(0x20)]
        internal readonly int AddressOfNames;
        [FieldOffset(0x24)]
        internal readonly int AddressOfNameOrdinals;
    }
}