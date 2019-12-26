namespace Lunar.PortableExecutable.Structures
{
    internal sealed class ImportedFunction
    {
        internal string Name { get; }

        internal int Offset { get; }

        internal short Ordinal { get; }

        internal ImportedFunction(string name, int offset, short ordinal)
        {
            Name = name;

            Offset = offset;

            Ordinal = ordinal;
        }
    }
}