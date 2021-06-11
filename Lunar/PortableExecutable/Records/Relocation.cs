using Lunar.Native.Enums;

namespace Lunar.PortableExecutable.Records
{
    internal sealed record Relocation(int Offset, RelocationType Type);
}