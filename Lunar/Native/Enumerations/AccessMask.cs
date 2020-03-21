using System;

namespace Lunar.Native.Enumerations
{
    [Flags]
    internal enum AccessMask
    {
        SpecificRightsAll = 0xFFFF,
        StandardRightsAll = 0x1F0000
    }
}