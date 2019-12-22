using System.Collections.Generic;

namespace Pluto.PortableExecutable.Structures
{
    internal sealed class ImportDescriptor
    {
        internal List<ImportedFunction> Functions { get; }

        internal string Name { get; set; }

        internal ImportDescriptor(List<ImportedFunction> functions, string name)
        {
            Functions = functions;

            Name = name;
        }
    }
}