using System.Collections.Generic;

namespace Lunar.PortableExecutable.Structures
{
    internal sealed record ImportDescriptor(IEnumerable<ImportedFunction> Functions, string Name);
}