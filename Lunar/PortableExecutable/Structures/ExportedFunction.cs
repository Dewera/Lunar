namespace Lunar.PortableExecutable.Structures
{
    internal sealed class ExportedFunction
    {
        internal string? ForwarderString { get; }

        internal string Name { get; }

        internal int Ordinal { get; }

        internal int Rva { get; }

        internal ExportedFunction(string? forwarderString, string name, int ordinal, int rva)
        {
            ForwarderString = forwarderString;

            Name = name;

            Ordinal = ordinal;

            Rva = rva;
        }
    }
}