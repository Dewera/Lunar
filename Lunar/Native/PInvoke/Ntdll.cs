using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Pluto.Native.Enumerations;
using Pluto.Native.SafeHandle;

namespace Pluto.Native.PInvoke
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