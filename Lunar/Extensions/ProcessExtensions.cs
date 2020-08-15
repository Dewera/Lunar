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
        internal static IntPtr AllocateBuffer(this Process process, int size, bool executable = false)
        {
            var bufferAddress = Kernel32.VirtualAllocEx(process.SafeHandle, IntPtr.Zero, size, AllocationType.Commit | AllocationType.Reserve, executable ? ProtectionType.ExecuteReadWrite : ProtectionType.ReadWrite);

            if (bufferAddress == IntPtr.Zero)
            {
                throw new Win32Exception();
            }

            return bufferAddress;
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

            if (isWow64Process)
            {
                return Architecture.X86;
            }

            return Architecture.X64;
        }

        internal static ProtectionType ProtectBuffer(this Process process, IntPtr address, int size, ProtectionType protectionType)
        {
            if (!Kernel32.VirtualProtectEx(process.SafeHandle, address, size, protectionType, out var oldProtectionType))
            {
                throw new Win32Exception();
            }

            return oldProtectionType;
        }

        internal static Span<T> ReadBuffer<T>(this Process process, IntPtr address, int size) where T : unmanaged
        {
            var buffer = new byte[size * Unsafe.SizeOf<T>()];

            if (!Kernel32.ReadProcessMemory(process.SafeHandle, address, out buffer[0], buffer.Length, out _))
            {
                throw new Win32Exception();
            }

            return MemoryMarshal.Cast<byte, T>(buffer);
        }

        internal static T ReadStructure<T>(this Process process, IntPtr address) where T : unmanaged
        {
            Span<byte> buffer = stackalloc byte[Unsafe.SizeOf<T>()];

            if (!Kernel32.ReadProcessMemory(process.SafeHandle, address, out buffer[0], buffer.Length, out _))
            {
                throw new Win32Exception();
            }

            return MemoryMarshal.Read<T>(buffer);
        }

        internal static void WriteBuffer<T>(this Process process, IntPtr address, Span<T> buffer) where T : unmanaged
        {
            var bufferByteSize = buffer.Length * Unsafe.SizeOf<T>();

            var oldProtectionType = process.ProtectBuffer(address, bufferByteSize, ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(process.SafeHandle, address, in MemoryMarshal.AsBytes(buffer)[0], bufferByteSize, out _))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                process.ProtectBuffer(address, bufferByteSize, oldProtectionType);
            }
        }

        internal static void WriteStructure<T>(this Process process, IntPtr address, T structure) where T : unmanaged
        {
            Span<byte> buffer = stackalloc byte[Unsafe.SizeOf<T>()];

            MemoryMarshal.Write(buffer, ref structure);

            var oldProtectionType = process.ProtectBuffer(address, buffer.Length, ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(process.SafeHandle, address, in buffer[0], buffer.Length, out _))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                process.ProtectBuffer(address, buffer.Length, oldProtectionType);
            }
        }
    }
}