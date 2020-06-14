using System;
using System.Runtime.InteropServices;
using Lunar.Native.Enumerations;
using Lunar.Native.SafeHandle;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke
{
    internal static class Ntdll
    {
        [DllImport("ntdll.dll", ExactSpelling = true)]
        internal static extern NtStatus NtCreateThreadEx(out SafeWin32Handle threadHandle, AccessMask accessMask, IntPtr objectAttributes, SafeProcessHandle processHandle, IntPtr startAddress, IntPtr startParameter, ThreadCreationFlags flags, IntPtr zeroBits, int stackSize, int maximumStackSize, IntPtr attributeList);

        [DllImport("ntdll.dll", ExactSpelling = true)]
        internal static extern NtStatus NtQueryInformationProcess(SafeProcessHandle processHandle, ProcessInformationClass processInformationClass, out byte processInformation, int processInformationSize, out int returnLength);

        [DllImport("ntdll.dll", ExactSpelling = true)]
        internal static extern int RtlNtStatusToDosError(NtStatus ntStatus);
    }
}