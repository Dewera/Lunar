using System;
using System.Runtime.InteropServices;
using Lunar.Native.Enumerations;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke
{
    internal static class Dbghelp
    {
        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool SymCleanup(SafeProcessHandle processHandle);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool SymFromName(SafeProcessHandle processHandle, string name, ref byte symbolInfo);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool SymInitialize(SafeProcessHandle processHandle, string? userSearchPath, bool invadeProcess);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern long SymLoadModuleEx(SafeProcessHandle processHandle, IntPtr fileHandle, string imageName, string? moduleName, long baseOfDll, int dllSize, IntPtr data, int flags);

        [DllImport("dbghelp.dll")]
        internal static extern void SymSetOptions(SymbolOptions symbolOptions);
    }
}