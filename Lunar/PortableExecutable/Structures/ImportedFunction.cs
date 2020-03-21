namespace Lunar.PortableExecutable.Structures
{
    internal sealed class ImportedFunction
    {
        internal string? Name { get; }

        internal int Offset { get; }

        internal int Ordinal { get; }

        internal ImportedFunction(string? name, int offset, int ordinal)
        {
            Name = name;

            Offset = offset;

            Ordinal = ordinal;
        }
    }
}