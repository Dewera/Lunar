using System.Collections.Generic;
using System.Collections.Immutable;

namespace Lunar.PortableExecutable.Structures
{
    internal sealed class ImportDescriptor
    {
        internal ImmutableArray<ImportedFunction> Functions { get; }

        internal string Name { get; }

        internal ImportDescriptor(IEnumerable<ImportedFunction> functions, string name)
        {
            Functions = functions.ToImmutableArray();

            Name = name;
        }
    }
}