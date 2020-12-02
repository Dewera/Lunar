using System;
using System.Runtime.InteropServices;
using Lunar.Native.Enumerations;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke
{
    internal static class Dbghelp
    {
        [DllImport("dbghelp.dll")]
        internal static extern void SymCleanup(SafeProcessHandle processHandle);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool SymFromName(SafeProcessHandle processHandle, string name, out byte symbol);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool SymInitialize(SafeProcessHandle processHandle, string? searchPath, bool invadeProcess);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern int SymLoadModule(SafeProcessHandle processHandle, IntPtr fileHandle, string imageName, string? moduleName, int dllBase, int dllSize);

        [DllImport("dbghelp.dll")]
        internal static extern void SymSetOptions(SymbolOptions options);
    }
}