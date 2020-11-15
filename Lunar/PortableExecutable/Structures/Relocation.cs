using Lunar.Native.Enumerations;

namespace Lunar.PortableExecutable.Structures
{
    internal sealed record Relocation(int Offset, RelocationType Type);
}