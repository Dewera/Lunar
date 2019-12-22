using Pluto.Native.Enumerations;

namespace Pluto.PortableExecutable.Structures
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