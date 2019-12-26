namespace Lunar.Native.Enumerations
{
    internal enum ProtectionType
    {
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40
    }
}