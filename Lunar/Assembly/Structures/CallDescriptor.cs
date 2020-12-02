using System;

namespace Lunar.Assembly.Structures
{
    internal sealed record CallDescriptor32(IntPtr Address, int[] Arguments, IntPtr ReturnAddress);

    internal sealed record CallDescriptor64(IntPtr Address, long[] Arguments, IntPtr ReturnAddress);
}