namespace Lunar.PortableExecutable.Structures
{
    internal sealed class ImportedFunction
    {
        internal int IatOffset { get; }

        internal string? Name { get; }

        internal int Ordinal { get; }

        internal ImportedFunction(int iatOffset, string? name, int ordinal)
        {
            IatOffset = iatOffset;

            Name = name;

            Ordinal = ordinal;
        }
    }
}