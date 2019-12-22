namespace Pluto.PortableExecutable.Structures
{
    internal sealed class ExportedFunction
    {
        internal string Name { get; set; }

        internal int Offset { get; }

        internal short Ordinal { get; }

        internal ExportedFunction(string name, int offset, short ordinal)
        {
            Name = name;

            Offset = offset;

            Ordinal = ordinal;
        }
    }
}