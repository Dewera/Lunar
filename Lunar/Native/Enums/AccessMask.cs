using System;

namespace Lunar.Native.Enums
{
    [Flags]
    internal enum AccessMask
    {
        SpecificRightsAll = 0xFFFF,
        StandardRightsAll = 0x1F0000
    }
}