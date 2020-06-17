using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;

namespace Lunar.Extensions
{
    internal static class ProcessExtensions
    {
        internal static IntPtr AllocateBuffer(this Process process, int bufferSize, bool executable = false)
        {
            const AllocationType allocationType = AllocationType.Commit | AllocationType.Reserve;

            var protectionType = executable ? ProtectionType.ExecuteReadWrite : ProtectionType.ReadWrite;

            var bufferAddress = Kernel32.VirtualAllocEx(process.SafeHandle, IntPtr.Zero, bufferSize, allocationType, protectionType);

            if (bufferAddress == IntPtr.Zero)
            {
                throw new Win32Exception();
            }

            return bufferAddress;
        }

        internal static void FreeBuffer(this Process process, IntPtr bufferAddress)
        {
            if (!Kernel32.VirtualFreeEx(process.SafeHandle, bufferAddress, 0, FreeType.Release))
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

        internal static ProtectionType ProtectBuffer(this Process process, IntPtr bufferAddress, int bufferSize, ProtectionType protectionType)
        {
            if (!Kernel32.VirtualProtectEx(process.SafeHandle, bufferAddress, bufferSize, protectionType, out var oldProtectionType))
            {
                throw new Win32Exception();
            }

            return oldProtectionType;
        }

        internal static T QueryInformation<T>(this Process process, ProcessInformationClass informationClass) where T : unmanaged
        {
            Span<byte> informationBlock = stackalloc byte[Unsafe.SizeOf<T>()];

            var ntStatus = Ntdll.NtQueryInformationProcess(process.SafeHandle, informationClass, out informationBlock[0], informationBlock.Length, out _);

            if (ntStatus != NtStatus.Success)
            {
                throw new Win32Exception(Ntdll.RtlNtStatusToDosError(ntStatus));
            }

            return MemoryMarshal.Read<T>(informationBlock);
        }

        internal static Span<T> ReadArray<T>(this Process process, IntPtr arrayAddress, int arraySize) where T : unmanaged
        {
            var arrayBlock = new Span<byte>(new byte[arraySize * Unsafe.SizeOf<T>()]);

            if (!Kernel32.ReadProcessMemory(process.SafeHandle, arrayAddress, out arrayBlock[0], arrayBlock.Length, out _))
            {
                throw new Win32Exception();
            }

            return MemoryMarshal.Cast<byte, T>(arrayBlock);
        }

        internal static T ReadStructure<T>(this Process process, IntPtr structureAddress) where T : unmanaged
        {
            Span<byte> structureBlock = stackalloc byte[Unsafe.SizeOf<T>()];

            if (!Kernel32.ReadProcessMemory(process.SafeHandle, structureAddress, out structureBlock[0], structureBlock.Length, out _))
            {
                throw new Win32Exception();
            }

            return MemoryMarshal.Read<T>(structureBlock);
        }

        internal static void WriteArray<T>(this Process process, IntPtr writeAddress, Span<T> array) where T : unmanaged
        {
            var oldProtectionType = process.ProtectBuffer(writeAddress, array.Length * Unsafe.SizeOf<T>(), ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(process.SafeHandle, writeAddress, in MemoryMarshal.AsBytes(array)[0], array.Length * Unsafe.SizeOf<T>(), out _))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                process.ProtectBuffer(writeAddress, array.Length * Unsafe.SizeOf<T>(), oldProtectionType);
            }
        }

        internal static void WriteStructure<T>(this Process process, IntPtr writeAddress, T structure) where T : unmanaged
        {
            Span<byte> structureBlock = stackalloc byte[Unsafe.SizeOf<T>()];

            MemoryMarshal.Write(structureBlock, ref structure);

            var oldProtectionType = process.ProtectBuffer(writeAddress, structureBlock.Length, ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(process.SafeHandle, writeAddress, in structureBlock[0], structureBlock.Length, out _))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                process.ProtectBuffer(writeAddress, structureBlock.Length, oldProtectionType);
            }
        }
    }
}