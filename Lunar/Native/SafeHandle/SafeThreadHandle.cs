using Microsoft.Win32.SafeHandles;
using Pluto.Native.PInvoke;

namespace Pluto.Native.SafeHandle
{
    internal sealed class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeThreadHandle() : base(true) { }

        protected override bool ReleaseHandle()
        {
            return Kernel32.CloseHandle(handle);
        }
    }
}