using Lunar.Native.Enumerations;

namespace Lunar.PortableExecutable.Structures
{
    internal sealed class BaseRelocation
    {
        internal int Offset { get; }

        internal BaseRelocationType Type { get; }

        internal BaseRelocation(int offset, BaseRelocationType type)
        {
            Offset = offset;

            Type = type;
        }
    }
}