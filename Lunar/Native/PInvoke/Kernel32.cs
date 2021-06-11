using System;
using System.Runtime.InteropServices;
using Lunar.Native.Enums;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke
{
    internal static class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        internal static extern SafeProcessHandle GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool IsWow64Process(SafeProcessHandle processHandle, out bool isWow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool K32EnumProcessModulesEx(SafeProcessHandle processHandle, out byte bytes, int size, out int sizeNeeded, ModuleType moduleType);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool K32GetModuleFileNameEx(SafeProcessHandle processHandle, IntPtr address, out byte bytes, int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(SafeProcessHandle processHandle, IntPtr address, out byte bytes, nint size, IntPtr bytesReadCount);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAllocEx(SafeProcessHandle processHandle, IntPtr address, nint size, AllocationType allocationType, ProtectionType protectionType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualFreeEx(SafeProcessHandle processHandle, IntPtr address, nint size, FreeType freeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualProtectEx(SafeProcessHandle processHandle, IntPtr address, nint size, ProtectionType protectionType, out ProtectionType oldProtectionType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int WaitForSingleObject(SafeHandle objectHandle, int milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(SafeProcessHandle processHandle, IntPtr address, in byte bytes, nint size, IntPtr bytesWrittenCount);
    }
}