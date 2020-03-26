using System;

namespace Lunar.Native.Enumerations
{
    [Flags]
    internal enum ThreadCreationFlags
    {
        SkipThreadAttach = 0x2,
        HideFromDebugger = 0x4
    }
}