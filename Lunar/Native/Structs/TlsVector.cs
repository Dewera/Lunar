using System.Runtime.InteropServices;

namespace Lunar.Native.Structs
{
    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal readonly struct TlsVector32
    {
        [FieldOffset(0x0)]
        private readonly int Length;
        [FieldOffset(0x4)]
        internal readonly int PreviousDeferredTlsVector;

        internal TlsVector32(int length, int previousDeferredTlsVector)
        {
            Length = length;
            PreviousDeferredTlsVector = previousDeferredTlsVector;
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal readonly struct TlsVector64
    {
        [FieldOffset(0x0)]
        private readonly int Length;
        [FieldOffset(0x8)]
        internal readonly long PreviousDeferredTlsVector;

        internal TlsVector64(int length, long previousDeferredTlsVector)
        {
            Length = length;
            PreviousDeferredTlsVector = previousDeferredTlsVector;
        }
    }
}