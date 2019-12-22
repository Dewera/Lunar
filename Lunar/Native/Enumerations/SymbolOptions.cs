using System;

namespace Pluto.Native.Enumerations
{
    [Flags]
    internal enum SymbolOptions
    {
        UndecorateName = 0x02,
        DeferredLoads = 0x04,
        AutoPublics = 0x10000
    }
}