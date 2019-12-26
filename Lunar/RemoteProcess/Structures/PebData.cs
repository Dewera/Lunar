using System;

namespace Lunar.RemoteProcess.Structures
{
    internal sealed class PebData
    {
        internal IntPtr ApiSetMap { get; }

        internal IntPtr Loader { get; }

        internal PebData(IntPtr apiSetMap, IntPtr loader)
        {
            ApiSetMap = apiSetMap;

            Loader = loader;
        }
    }
}