using System.Runtime.InteropServices;
using Lunar.Native.Enums;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke;

internal static partial class Kernel32
{
    [LibraryImport("kernel32.dll", EntryPoint = "K32EnumProcessModulesEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool EnumProcessModulesEx(SafeProcessHandle processHandle, out byte bytes, int size, out int sizeNeeded, ModuleType moduleType);

    [LibraryImport("kernel32.dll", EntryPoint = "K32GetModuleFileNameExW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetModuleFileNameEx(SafeProcessHandle processHandle, nint address, out byte bytes, int size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsWow64Process(SafeProcessHandle processHandle, [MarshalAs(UnmanagedType.Bool)] out bool isWow64Process);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ReadProcessMemory(SafeProcessHandle processHandle, nint address, out byte bytes, nint size, nint bytesReadCount);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial nint VirtualAllocEx(SafeProcessHandle processHandle, nint address, nint size, AllocationType allocationType, ProtectionType protectionType);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool VirtualFreeEx(SafeProcessHandle processHandle, nint address, nint size, FreeType freeType);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool VirtualProtectEx(SafeProcessHandle processHandle, nint address, nint size, ProtectionType protectionType, out ProtectionType oldProtectionType);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial int WaitForSingleObject(SafeHandle objectHandle, int milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool WriteProcessMemory(SafeProcessHandle processHandle, nint address, in byte bytes, nint size, nint bytesWrittenCount);
}