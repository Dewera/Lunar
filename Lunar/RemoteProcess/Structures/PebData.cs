using System;

namespace Lunar.RemoteProcess.Structures
{
    internal sealed class PebData
    {
        internal IntPtr ApiSetMapAddress { get; }

        internal IntPtr LoaderAddress { get; }

        internal PebData(IntPtr apiSetMapAddress, IntPtr loaderAddress)
        {
            ApiSetMapAddress = apiSetMapAddress;

            LoaderAddress = loaderAddress;
        }
    }
}