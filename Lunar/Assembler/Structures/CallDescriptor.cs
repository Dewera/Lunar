using System;
using System.Collections.Generic;

namespace Lunar.Assembler.Structures
{
    internal sealed record CallDescriptor32(IntPtr Address, IEnumerable<int> Arguments, IntPtr ReturnAddress);

    internal sealed record CallDescriptor64(IntPtr Address, IEnumerable<long> Arguments, IntPtr ReturnAddress);
}