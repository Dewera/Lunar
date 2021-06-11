using System;

namespace Lunar.Native.Enums
{
    [Flags]
    internal enum GuardFlags
    {
        Instrumented = 0x100,
        SecurityCookieUnused = 0x800,
        ExportSuppressionInfoPresent = 0x4000
    }
}