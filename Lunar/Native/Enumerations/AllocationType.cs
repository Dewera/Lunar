using System;

namespace Lunar.Native.Enumerations
{
    [Flags]
    internal enum AllocationType
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        TopDown = 0x100000
    }
}