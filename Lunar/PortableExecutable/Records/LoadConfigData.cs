using Lunar.Native.Enums;

namespace Lunar.PortableExecutable.Records;

internal sealed record LoadConfigData(ExceptionData? ExceptionTable, GuardFlags GuardFlags, SecurityCookie? SecurityCookie);