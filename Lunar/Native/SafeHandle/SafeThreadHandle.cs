using Lunar.Native.PInvoke;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.SafeHandle
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