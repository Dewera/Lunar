namespace Lunar.Helpers;

internal static class BitmapManager
{
    internal static void ClearBit(ref Span<byte> bitmap, int bitIndex)
    {
        var bitmask = 1 << bitIndex % 8;
        bitmap[bitIndex / 8] &= (byte) ~bitmask;
    }

    internal static int FindClearBitAndSet(ref Span<byte> bitmap)
    {
        var byteIndex = 0;

        foreach (var @byte in bitmap)
        {
            if (@byte == byte.MaxValue)
            {
                byteIndex += 1;
                continue;
            }

            // Find the first available bit in the byte

            var bitIndex = 0;

            while ((@byte & 1 << bitIndex) != 0)
            {
                bitIndex += 1;
            }

            // Set the bit

            bitmap[byteIndex] |= (byte) (1 << bitIndex);

            return byteIndex * 8 + bitIndex;
        }

        return -1;
    }
}