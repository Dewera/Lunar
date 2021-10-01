using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 40)]
    internal readonly struct LdrpTlsEntry32
    {
        [FieldOffset(0x0)]
        internal readonly ListEntry32 EntryLinks;
        [FieldOffset(0x8)]
        private readonly ImageTlsDirectory32 TlsDirectory;
        [FieldOffset(0x24)]
        internal readonly int Index;

        internal LdrpTlsEntry32(ListEntry32 entryLinks, ImageTlsDirectory32 tlsDirectory, int index)
        {
            EntryLinks = entryLinks;
            TlsDirectory = tlsDirectory;
            Index = index;
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 72)]
    internal readonly struct LdrpTlsEntry64
    {
        [FieldOffset(0x0)]
        internal readonly ListEntry64 EntryLinks;
        [FieldOffset(0x10)]
        private readonly ImageTlsDirectory64 TlsDirectory;
        [FieldOffset(0x40)]
        internal readonly int Index;

        internal LdrpTlsEntry64(ListEntry64 entryLinks, ImageTlsDirectory64 tlsDirectory, int index)
        {
            EntryLinks = entryLinks;
            TlsDirectory = tlsDirectory;
            Index = index;
        }
    }
}