using System;
using System.Collections.Generic;

namespace Lunar.Shellcode.Structures
{
    internal sealed record CallDescriptor<T>(IntPtr Address, IList<T> Arguments, IntPtr ReturnAddress);
}