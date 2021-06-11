using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Native.Enums;
using Lunar.Native.PInvoke;

namespace Lunar.Extensions
{
    internal static class ProcessExtensions
    {
        internal static IntPtr AllocateBuffer(this Process process, int size, ProtectionType protectionType)
        {
            var address = Kernel32.VirtualAllocEx(process.SafeHandle, IntPtr.Zero, size, AllocationType.Commit | AllocationType.Reserve, protectionType);

            if (address == IntPtr.Zero)
            {
                throw new Win32Exception();
            }

            return address;
        }

        internal static void CreateThread(this Process process, IntPtr address)
        {
            var status = Ntdll.RtlCreateUserThread(process.SafeHandle, IntPtr.Zero, false, 0, 0, 0, address, IntPtr.Zero, out var threadHandle, IntPtr.Zero);

            if (status != NtStatus.Success)
            {
                throw new Win32Exception(Ntdll.RtlNtStatusToDosError(status));
            }

            using (threadHandle)
            {
                if (Kernel32.WaitForSingleObject(threadHandle, int.MaxValue) == -1)
                {
                    throw new Win32Exception();
                }
            }
        }

        internal static void FreeBuffer(this Process process, IntPtr address)
        {
            if (!Kernel32.VirtualFreeEx(process.SafeHandle, address, 0, FreeType.Release))
            {
                throw new Win32Exception();
            }
        }

        internal static Architecture GetArchitecture(this Process process)
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                return Architecture.X86;
            }

            if (!Kernel32.IsWow64Process(process.SafeHandle, out var isWow64Process))
            {
                throw new Win32Exception();
            }

            return isWow64Process ? Architecture.X86 : Architecture.X64;
        }

        internal static ProtectionType ProtectBuffer(this Process process, IntPtr address, int size, ProtectionType protectionType)
        {
            if (!Kernel32.VirtualProtectEx(process.SafeHandle, address, size, protectionType, out var oldProtectionType))
            {
                throw new Win32Exception();
            }

            return oldProtectionType;
        }

        internal static Span<T> ReadSpan<T>(this Process process, IntPtr address, int elements) where T : unmanaged
        {
            var spanBytes = new byte[Unsafe.SizeOf<T>() * elements];

            if (!Kernel32.ReadProcessMemory(process.SafeHandle, address, out spanBytes[0], spanBytes.Length, IntPtr.Zero))
            {
                throw new Win32Exception();
            }

            return MemoryMarshal.Cast<byte, T>(spanBytes);
        }

        internal static T ReadStruct<T>(this Process process, IntPtr address) where T : unmanaged
        {
            Span<byte> structBytes = stackalloc byte[Unsafe.SizeOf<T>()];

            if (!Kernel32.ReadProcessMemory(process.SafeHandle, address, out structBytes[0], structBytes.Length, IntPtr.Zero))
            {
                throw new Win32Exception();
            }

            return MemoryMarshal.Read<T>(structBytes);
        }

        internal static void WriteSpan<T>(this Process process, IntPtr address, Span<T> span) where T : unmanaged
        {
            var spanBytes = MemoryMarshal.AsBytes(span);
            var oldProtectionType = process.ProtectBuffer(address, spanBytes.Length, ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(process.SafeHandle, address, in spanBytes[0], spanBytes.Length, IntPtr.Zero))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                process.ProtectBuffer(address, spanBytes.Length, oldProtectionType);
            }
        }

        internal static void WriteString(this Process process, IntPtr address, string @string)
        {
            var stringBytes = Encoding.Unicode.GetBytes(@string);
            var oldProtectionType = process.ProtectBuffer(address, stringBytes.Length, ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(process.SafeHandle, address, in stringBytes[0], stringBytes.Length, IntPtr.Zero))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                process.ProtectBuffer(address, stringBytes.Length, oldProtectionType);
            }
        }

        internal static void WriteStruct<T>(this Process process, IntPtr address, T @struct) where T : unmanaged
        {
            var structBytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref @struct, 1));
            var oldProtectionType = process.ProtectBuffer(address, structBytes.Length, ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(process.SafeHandle, address, in structBytes[0], structBytes.Length, IntPtr.Zero))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                process.ProtectBuffer(address, structBytes.Length, oldProtectionType);
            }
        }
    }
}