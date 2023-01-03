using System.Runtime.InteropServices;
using Lunar.Native.Enums;
using Lunar.Native.Structs;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke;

internal static partial class Dbghelp
{
    [LibraryImport("dbghelp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SymCleanup(SafeProcessHandle processHandle);

    [LibraryImport("dbghelp.dll", EntryPoint = "SymFromNameW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SymFromName(SafeProcessHandle processHandle, string name, out SymbolInfo symbolInfo);

    [LibraryImport("dbghelp.dll", EntryPoint = "SymInitializeW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SymInitialize(SafeProcessHandle processHandle, nint searchPath, [MarshalAs(UnmanagedType.Bool)] bool invadeProcess);

    [LibraryImport("dbghelp.dll", EntryPoint = "SymLoadModuleExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial long SymLoadModule(SafeProcessHandle processHandle, nint fileHandle, string imageName, nint moduleName, long dllBase, int dllSize, nint data, int flags);

    [LibraryImport("dbghelp.dll", SetLastError = true)]
    internal static partial SymbolOptions SymSetOptions(SymbolOptions options);
}