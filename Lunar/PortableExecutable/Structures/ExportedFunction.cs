namespace Lunar.PortableExecutable.Structures
{
    internal sealed class ExportedFunction
    {
        internal string Name { get; }

        internal int Offset { get; }

        internal int Ordinal { get; }

        internal ExportedFunction(string name, int offset, int ordinal)
        {
            Name = name;

            Offset = offset;

            Ordinal = ordinal;
        }
    }
}