using System;
using System.Runtime.InteropServices;
using Lunar.Native.Enumerations;
using Lunar.Native.SafeHandle;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke
{
    internal static class Ntdll
    {
        [DllImport("ntdll.dll")]
        internal static extern NtStatus NtQueryInformationProcess(SafeProcessHandle processHandle, ProcessInformationClass processInformationClass, ref byte processInformation, int processInformationLength, out int returnLength);

        [DllImport("ntdll.dll")]
        internal static extern NtStatus RtlCreateUserThread(SafeProcessHandle processHandle, IntPtr securityDescriptor, bool createSuspended, int stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr startParameter, out SafeThreadHandle threadHandle, IntPtr clientId);

        [DllImport("ntdll.dll")]
        internal static extern int RtlNtStatusToDosError(NtStatus ntStatus);
    }
}