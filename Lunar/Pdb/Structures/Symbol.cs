namespace Lunar.Pdb.Structures
{
    internal sealed class Symbol
    {
        internal string Name { get; }

        internal int Rva { get; }

        internal Symbol(string name, int rva)
        {
            Name = name;

            Rva = rva;
        }
    }
}