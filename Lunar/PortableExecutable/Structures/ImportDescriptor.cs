using System.Collections.Generic;

namespace Lunar.PortableExecutable.Structures
{
    internal sealed class ImportDescriptor
    {
        internal IEnumerable<ImportedFunction> Functions { get; }

        internal string Name { get; }

        internal ImportDescriptor(IEnumerable<ImportedFunction> functions, string name)
        {
            Functions = functions;

            Name = name;
        }
    }
}