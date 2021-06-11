using System;
using System.Collections.Generic;

namespace Lunar.Shellcode.Records
{
    internal sealed record CallDescriptor<T>(IntPtr Address, IList<T> Arguments, IntPtr ReturnAddress);
}