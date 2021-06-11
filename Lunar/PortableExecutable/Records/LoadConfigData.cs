using Lunar.Native.Enums;

namespace Lunar.PortableExecutable.Records
{
    internal sealed record LoadConfigData(ExceptionTable? ExceptionTable, GuardFlags GuardFlags, SecurityCookie? SecurityCookie);
}