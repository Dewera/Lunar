using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal readonly struct TlsReclaimTableEntry32
    {
        [FieldOffset(0x0)]
        internal readonly int TlsVector;

        internal TlsReclaimTableEntry32(int tlsVector)
        {
            TlsVector = tlsVector;
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal readonly struct TlsReclaimTableEntry64
    {
        [FieldOffset(0x0)]
        internal readonly long TlsVector;

        internal TlsReclaimTableEntry64(long tlsVector)
        {
            TlsVector = tlsVector;
        }
    }
}