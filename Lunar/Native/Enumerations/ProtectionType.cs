using System;

namespace Lunar.Native.Enumerations
{
    [Flags]
    internal enum ProtectionType
    {
        NoAccess = 0x1,
        ReadOnly = 0x2,
        ReadWrite = 0x4,
        WriteCopy = 0x8,
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        NoCache = 0x200
    }
}