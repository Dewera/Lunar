using System;
using System.Collections.Generic;

namespace Lunar.Assembly.Structures
{
    internal sealed record CallDescriptor32(IntPtr Address, IList<int> Arguments, IntPtr ReturnAddress);

    internal sealed record CallDescriptor64(IntPtr Address, IList<long> Arguments, IntPtr ReturnAddress);
}