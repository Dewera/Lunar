using System.Runtime.InteropServices;
using Lunar.Native.Enums;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Native.PInvoke;

internal static partial class Ntdll
{
    [LibraryImport("ntdll.dll")]
    internal static partial NtStatus NtQueryInformationProcess(SafeProcessHandle processHandle, ProcessInformationType informationType, out byte information, int informationSize, nint returnLength);

    [LibraryImport("ntdll.dll")]
    internal static partial NtStatus RtlCreateUserThread(SafeProcessHandle processHandle, nint securityDescriptor, [MarshalAs(UnmanagedType.Bool)] bool createSuspended, int stackZeroBits, nint stackReserved, nint stackCommit, nint startAddress, nint parameter, out SafeAccessTokenHandle threadHandle, nint clientId);

    [LibraryImport("ntdll.dll")]
    internal static partial nint RtlGetCurrentPeb();

    [LibraryImport("ntdll.dll")]
    internal static partial int RtlNtStatusToDosError(NtStatus status);
}