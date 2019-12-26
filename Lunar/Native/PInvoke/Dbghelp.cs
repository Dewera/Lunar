using System;
using System.Runtime.InteropServices;
using Lunar.Native.Enumerations;
using Lunar.Native.Structures;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke
{
    internal static class Dbghelp
    {
        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool SymCleanup(SafeProcessHandle processHandle);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool SymFromName(SafeProcessHandle processHandle, string name, ref SymbolInfo symbolInfo);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool SymInitialize(SafeProcessHandle processHandle, string? userSearchPath, bool invadeProcess);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern long SymLoadModule64(SafeProcessHandle processHandle, IntPtr fileHandle, string imageName, string? moduleName, long baseOfDll, int sizeOfDll);

        [DllImport("dbghelp.dll")]
        internal static extern void SymSetOptions(SymbolOptions symbolOptions);
    }
}