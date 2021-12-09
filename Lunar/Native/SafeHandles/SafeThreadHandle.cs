using Lunar.Native.PInvoke;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.SafeHandles;

internal sealed class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeThreadHandle() : base(true) { }

    protected override bool ReleaseHandle()
    {
        return Kernel32.CloseHandle(handle);
    }
}