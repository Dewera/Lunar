using System.Runtime.InteropServices;
using Lunar.Native.Enums;
using Lunar.Native.Structs;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke;

internal static class Dbghelp
{
    [DllImport("dbghelp.dll", SetLastError = true)]
    internal static extern bool SymCleanup(SafeProcessHandle processHandle);

    [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool SymFromName(SafeProcessHandle processHandle, string name, out SymbolInfo symbolInfo);

    [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool SymInitialize(SafeProcessHandle processHandle, IntPtr searchPath, bool invadeProcess);

    [DllImport("dbghelp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern long SymLoadModuleEx(SafeProcessHandle processHandle, IntPtr fileHandle, string imageName, IntPtr moduleName, long dllBase, int dllSize, IntPtr data, int flags);

    [DllImport("dbghelp.dll")]
    internal static extern SymbolOptions SymSetOptions(SymbolOptions options);

    [DllImport("dbghelp.dll", SetLastError = true)]
    internal static extern bool SymUnloadModule64(SafeProcessHandle processHandle, long dllBase);
}