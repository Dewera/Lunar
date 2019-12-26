using Lunar.Native.Enumerations;

namespace Lunar.PortableExecutable.Structures
{
    internal sealed class Relocation
    {
        internal int Offset { get; }

        internal RelocationType Type { get; }

        internal Relocation(int offset, RelocationType type)
        {
            Offset = offset;

            Type = type;
        }
    }
}