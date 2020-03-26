using System;

namespace Lunar.Native.Enumerations
{
    [Flags]
    internal enum SymbolOptions
    {
        UndecorateName = 0x2,
        DeferredLoads = 0x4
    }
}