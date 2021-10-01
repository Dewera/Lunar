using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native.Enums;
using Lunar.Native.PInvoke;

namespace Lunar.Extensions
{
    internal static class ProcessThreadExtensions
    {
        internal static T QueryInformation<T>(this ProcessThread thread, ThreadInformationType informationType) where T : unmanaged
        {
            using var threadHandle = Kernel32.OpenThread(AccessMask.SpecificRightsAll | AccessMask.StandardRightsAll, false, thread.Id);

            if (threadHandle.IsInvalid)
            {
                throw new Win32Exception();
            }

            Span<byte> informationBytes = stackalloc byte[Unsafe.SizeOf<T>()];
            var status = Ntdll.NtQueryInformationThread(threadHandle, informationType, out informationBytes[0], informationBytes.Length, IntPtr.Zero);

            if (status != NtStatus.Success)
            {
                throw new Win32Exception(Ntdll.RtlNtStatusToDosError(status));
            }

            return MemoryMarshal.Read<T>(informationBytes);
        }

        internal static bool IsActive(this ProcessThread thread)
        {
            using var threadHandle = Kernel32.OpenThread(AccessMask.SpecificRightsAll | AccessMask.StandardRightsAll, false, thread.Id);

            if (threadHandle.IsInvalid)
            {
                return false;
            }

            if (!Kernel32.GetExitCodeThread(threadHandle, out var exitCode))
            {
                throw new Win32Exception();
            }

            return exitCode == ThreadExitCode.StillActive;
        }
    }
}