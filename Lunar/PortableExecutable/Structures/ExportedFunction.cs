namespace Lunar.PortableExecutable.Structures
{
    internal sealed class ExportedFunction
    {
        internal string? ForwarderString { get; }

        internal string Name { get; }

        internal int Offset { get; }

        internal int Ordinal { get; }

        internal ExportedFunction(string? forwarderString, string name, int offset, int ordinal)
        {
            ForwarderString = forwarderString;

            Name = name;

            Offset = offset;

            Ordinal = ordinal;
        }
    }
}