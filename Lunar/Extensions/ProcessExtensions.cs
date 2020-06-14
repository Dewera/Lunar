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
        internal static IntPtr AllocateBuffer(this Process process, int size, bool executable = false, bool topDown = false)
        {
            var allocationType = AllocationType.Commit | AllocationType.Reserve;

            if (topDown)
            {
                allocationType |= AllocationType.TopDown;
            }

            var protectionType = executable ? ProtectionType.ExecuteReadWrite : ProtectionType.ReadWrite;

            var buffer = Kernel32.VirtualAllocEx(process.SafeHandle, IntPtr.Zero, size, allocationType, protectionType);

            if (buffer == IntPtr.Zero)
            {
                throw new Win32Exception();
            }

            return buffer;
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

        internal static Span<TStructure> ReadBuffer<TStructure>(this Process process, IntPtr address, int size) where TStructure : unmanaged
        {
            var buffer = new byte[Unsafe.SizeOf<TStructure>() * size];

            if (!Kernel32.ReadProcessMemory(process.SafeHandle, address, out buffer[0], buffer.Length, out _))
            {
                throw new Win32Exception();
            }

            return MemoryMarshal.Cast<byte, TStructure>(buffer);
        }

        internal static TStructure ReadStructure<TStructure>(this Process process, IntPtr address) where TStructure : unmanaged
        {
            var buffer = process.ReadBuffer<byte>(address, Unsafe.SizeOf<TStructure>());

            return MemoryMarshal.Read<TStructure>(buffer);
        }

        internal static void WriteBuffer<TStructure>(this Process process, IntPtr address, Span<TStructure> buffer, bool adjustProtection = false) where TStructure : unmanaged
        {
            if (adjustProtection)
            {
                var oldProtectionType = process.ProtectBuffer(address, buffer.Length * Unsafe.SizeOf<TStructure>(), ProtectionType.ReadWrite);

                try
                {
                    if (!Kernel32.WriteProcessMemory(process.SafeHandle, address, in MemoryMarshal.AsBytes(buffer)[0], buffer.Length * Unsafe.SizeOf<TStructure>(), out _))
                    {
                        throw new Win32Exception();
                    }
                }

                finally
                {
                    process.ProtectBuffer(address, buffer.Length * Unsafe.SizeOf<TStructure>(), oldProtectionType);
                }
            }

            else
            {
                if (!Kernel32.WriteProcessMemory(process.SafeHandle, address, in MemoryMarshal.AsBytes(buffer)[0], buffer.Length * Unsafe.SizeOf<TStructure>(), out _))
                {
                    throw new Win32Exception();
                }
            }
        }

        internal static void WriteStructure<TStructure>(this Process process, IntPtr address, TStructure structure, bool adjustProtection = false) where TStructure : unmanaged
        {
            Span<byte> buffer = stackalloc byte[Unsafe.SizeOf<TStructure>()];

            MemoryMarshal.Write(buffer, ref structure);

            process.WriteBuffer(address, buffer, adjustProtection);
        }
    }
}