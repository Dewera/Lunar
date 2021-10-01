using System;
using System.Runtime.InteropServices;
using Lunar.Native.Enums;
using Lunar.Native.SafeHandles;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke
{
    internal static class Ntdll
    {
        [DllImport("ntdll.dll")]
        internal static extern NtStatus NtQueryInformationProcess(SafeProcessHandle processHandle, ProcessInformationType informationType, out byte information, int informationSize, IntPtr returnLength);

        [DllImport("ntdll.dll")]
        internal static extern NtStatus NtQueryInformationThread(SafeThreadHandle threadHandle, ThreadInformationType informationType, out byte information, int informationSize, IntPtr returnLength);

        [DllImport("ntdll.dll")]
        internal static extern NtStatus RtlCreateUserThread(SafeProcessHandle processHandle, IntPtr securityDescriptor, bool createSuspended, int stackZeroBits, nint stackReserved, nint stackCommit, IntPtr startAddress, IntPtr parameter, out SafeThreadHandle threadHandle, IntPtr clientId);

        [DllImport("ntdll.dll")]
        internal static extern IntPtr RtlGetCurrentPeb();

        [DllImport("ntdll.dll")]
        internal static extern int RtlNtStatusToDosError(NtStatus status);
    }
}