using System;
using System.Runtime.InteropServices;
using Lunar.Native.Enumerations;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke
{
    internal static class Dbghelp
    {
        [DllImport("dbghelp.dll", ExactSpelling = true)]
        internal static extern void SymCleanup(SafeProcessHandle processHandle);

        [DllImport("dbghelp.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool SymFromName(SafeProcessHandle processHandle, string name, out byte symbolInfo);

        [DllImport("dbghelp.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool SymInitialize(SafeProcessHandle processHandle, string? userSearchPath, bool invadeProcess);

        [DllImport("dbghelp.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern long SymLoadModuleEx(SafeProcessHandle processHandle, IntPtr fileHandle, string imageName, string? moduleName, long baseOfDll, int dllSize, IntPtr data, int flags);

        [DllImport("dbghelp.dll", ExactSpelling = true)]
        internal static extern void SymSetOptions(SymbolOptions symbolOptions);
    }
}