using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Lunar.Shared;

namespace Lunar.Extensions
{
    internal static class ProcessExtensions
    {
        internal static IntPtr AllocateMemory(this Process process, int size, ProtectionType protectionType)
        {
            var block = Kernel32.VirtualAllocEx(process.SafeHandle, IntPtr.Zero, size, AllocationType.Commit | AllocationType.Reserve, protectionType);

            if (block == IntPtr.Zero)
            {
                throw ExceptionBuilder.BuildWin32Exception("VirtualAllocEx");
            }

            return block;
        }

        internal static void FreeMemory(this Process process, IntPtr baseAddress)
        {
            if (!Kernel32.VirtualFreeEx(process.SafeHandle, baseAddress, 0, FreeType.Release))
            {
                throw ExceptionBuilder.BuildWin32Exception("VirtualFreeEx");
            }
        }

        internal static Architecture GetArchitecture(this Process process)
        {
            if (!Kernel32.IsWow64Process(process.SafeHandle, out var isWow64Process))
            {
                throw ExceptionBuilder.BuildWin32Exception("IsWow64Process");
            }

            return isWow64Process ? Architecture.X86 : Architecture.X64;
        }
        
        internal static void ProtectMemory(this Process process, IntPtr baseAddress, int size, ProtectionType protectionType)
        {
            if (!Kernel32.VirtualProtectEx(process.SafeHandle, baseAddress, size, protectionType, out _))
            {
                throw ExceptionBuilder.BuildWin32Exception("VirtualProtectEx");
            }
        }

        internal static ReadOnlyMemory<byte> ReadMemory(this Process process, IntPtr baseAddress, int size)
        {
            var block = new byte[size];
            
            if (!Kernel32.ReadProcessMemory(process.SafeHandle, baseAddress, out block[0], block.Length, out _))
            {
                throw ExceptionBuilder.BuildWin32Exception("ReadProcessMemory");
            }

            return block;
        }

        internal static TStructure ReadStructure<TStructure>(this Process process, IntPtr baseAddress) where TStructure : unmanaged
        {
            var block = process.ReadMemory(baseAddress, Unsafe.SizeOf<TStructure>());
            
            return MemoryMarshal.Read<TStructure>(block.Span);
        }

        internal static void WriteMemory(this Process process, IntPtr baseAddress, ReadOnlyMemory<byte> block)
        {
            if (!Kernel32.WriteProcessMemory(process.SafeHandle, baseAddress, block.Span[0], block.Length, out _))
            {
                throw ExceptionBuilder.BuildWin32Exception("WriteProcessMemory");
            }
        }
    }
}