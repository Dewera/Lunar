using System;
using System.Runtime.InteropServices;
using Lunar.Native.Enumerations;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke
{
    internal static class Ntdll
    {
        [DllImport("ntdll.dll")]
        internal static extern NtStatus NtCreateThreadEx(out SafeWaitHandle threadHandle, AccessMask accessMask, IntPtr objectAttributes, SafeProcessHandle processHandle, IntPtr startAddress, IntPtr argument, ThreadCreationFlags flags, nint zeroBits, nint stackSize, nint maximumStackSize, IntPtr attributeList);

        [DllImport("ntdll.dll")]
        internal static extern NtStatus NtQueryInformationProcess(SafeProcessHandle processHandle, ProcessInformationType informationType, out byte information, int informationSize, out int returnLength);

        [DllImport("ntdll.dll")]
        internal static extern IntPtr RtlGetCurrentPeb();

        [DllImport("ntdll.dll")]
        internal static extern int RtlNtStatusToDosError(NtStatus status);
    }
}