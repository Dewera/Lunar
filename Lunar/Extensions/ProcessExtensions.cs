using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;

namespace Lunar.Extensions
{
    internal static class ProcessExtensions
    {
        internal static IntPtr AllocateMemory(this Process process, int size, bool executable = false)
        {
            var protectionType = executable ? ProtectionType.ExecuteReadWrite : ProtectionType.ReadWrite;

            var address = Kernel32.VirtualAllocEx(process.SafeHandle, IntPtr.Zero, size, AllocationType.Commit | AllocationType.Reserve, protectionType);

            if (address == IntPtr.Zero)
            {
                throw new Win32Exception();
            }

            return address;
        }

        internal static void CreateThread(this Process process, IntPtr address)
        {
            var status = Ntdll.NtCreateThreadEx(out var threadHandle, AccessMask.SpecificRightsAll | AccessMask.StandardRightsAll, IntPtr.Zero, process.SafeHandle, address, IntPtr.Zero, ThreadCreationFlags.HideFromDebugger | ThreadCreationFlags.SkipThreadAttach, 0, 0, 0, IntPtr.Zero);

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

        internal static void FreeMemory(this Process process, IntPtr address)
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

        internal static string GetProcessDirectoryPath(this Process process)
        {
            return process.MainModule!.FileName!;
        }

        internal static string GetSystemDirectoryPath(this Process process)
        {
            if (Environment.Is64BitOperatingSystem && process.GetArchitecture() == Architecture.X86)
            {
                return Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
            }

            return Environment.SystemDirectory;
        }

        internal static ProtectionType ProtectMemory(this Process process, IntPtr address, int size, ProtectionType protectionType)
        {
            if (!Kernel32.VirtualProtectEx(process.SafeHandle, address, size, protectionType, out var oldProtectionType))
            {
                throw new Win32Exception();
            }

            return oldProtectionType;
        }

        internal static T QueryInformation<T>(this Process process, ProcessInformationType informationType) where T : unmanaged
        {
            Span<byte> informationBytes = stackalloc byte[Unsafe.SizeOf<T>()];

            var status = Ntdll.NtQueryInformationProcess(process.SafeHandle, informationType, out informationBytes[0], informationBytes.Length, out _);

            if (status != NtStatus.Success)
            {
                throw new Win32Exception(Ntdll.RtlNtStatusToDosError(status));
            }

            return MemoryMarshal.Read<T>(informationBytes);
        }

        internal static Span<T> ReadArray<T>(this Process process, IntPtr address, int elements) where T : unmanaged
        {
            var arrayBytes = new byte[Unsafe.SizeOf<T>() * elements];

            if (!Kernel32.ReadProcessMemory(process.SafeHandle, address, out arrayBytes[0], arrayBytes.Length, out _))
            {
                throw new Win32Exception();
            }

            return MemoryMarshal.Cast<byte, T>(arrayBytes);
        }

        internal static string ReadString(this Process process, IntPtr address, int size)
        {
            Span<byte> stringBytes = stackalloc byte[size];

            if (!Kernel32.ReadProcessMemory(process.SafeHandle, address, out stringBytes[0], stringBytes.Length, out _))
            {
                throw new Win32Exception();
            }

            return Encoding.Unicode.GetString(stringBytes);
        }

        internal static T ReadStructure<T>(this Process process, IntPtr address) where T : unmanaged
        {
            Span<byte> structureBytes = stackalloc byte[Unsafe.SizeOf<T>()];

            if (!Kernel32.ReadProcessMemory(process.SafeHandle, address, out structureBytes[0], structureBytes.Length, out _))
            {
                throw new Win32Exception();
            }

            return MemoryMarshal.Read<T>(structureBytes);
        }

        internal static void WriteArray<T>(this Process process, IntPtr address, Span<T> array) where T : unmanaged
        {
            var arrayBytes = MemoryMarshal.AsBytes(array);

            var oldProtectionType = process.ProtectMemory(address, arrayBytes.Length, ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(process.SafeHandle, address, in arrayBytes[0], arrayBytes.Length, out _))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                process.ProtectMemory(address, arrayBytes.Length, oldProtectionType);
            }
        }

        internal static void WriteString(this Process process, IntPtr address, string @string)
        {
            var stringBytes = Encoding.Unicode.GetBytes(@string);

            var oldProtectionType = process.ProtectMemory(address, stringBytes.Length, ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(process.SafeHandle, address, in stringBytes[0], stringBytes.Length, out _))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                process.ProtectMemory(address, stringBytes.Length, oldProtectionType);
            }
        }

        internal static void WriteStructure<T>(this Process process, IntPtr address, T structure) where T : unmanaged
        {
            Span<byte> structureBytes = stackalloc byte[Unsafe.SizeOf<T>()];

            MemoryMarshal.Write(structureBytes, ref structure);

            var oldProtectionType = process.ProtectMemory(address, structureBytes.Length, ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(process.SafeHandle, address, in structureBytes[0], structureBytes.Length, out _))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                process.ProtectMemory(address, structureBytes.Length, oldProtectionType);
            }
        }
    }
}