using System;

namespace Lunar.Native.Enumerations
{
    [Flags]
    internal enum ThreadCreationFlags
    {
        SkipThreadAttach = 0x02,
        HideFromDebugger = 0x04
    }
}