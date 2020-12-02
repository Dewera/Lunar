using System;
using System.Runtime.InteropServices;
using Lunar.Native.Enumerations;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke
{
    internal static class Kernel32
    {
        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern SafeProcessHandle GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool IsWow64Process(SafeProcessHandle processHandle, out bool isWow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(SafeProcessHandle processHandle, IntPtr address, out byte bytes, nint size, out nint bytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAllocEx(SafeProcessHandle processHandle, IntPtr address, nint size, AllocationType allocationType, ProtectionType protectionType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualFreeEx(SafeProcessHandle processHandle, IntPtr address, nint size, FreeType freeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualProtectEx(SafeProcessHandle processHandle, IntPtr address, nint size, ProtectionType protectionType, out ProtectionType oldProtectionType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int WaitForSingleObject(SafeWaitHandle waitHandle, int milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(SafeProcessHandle processHandle, IntPtr address, in byte bytes, nint size, out nint bytesWritten);
    }
}