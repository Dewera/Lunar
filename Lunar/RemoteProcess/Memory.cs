using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Microsoft.Win32.SafeHandles;

namespace Lunar.RemoteProcess
{
    internal sealed class Memory
    {
        private readonly SafeProcessHandle _processHandle;

        internal Memory(SafeProcessHandle processHandle)
        {
            _processHandle = processHandle;
        }

        internal IntPtr Allocate(int size, ProtectionType protectionType)
        {
            var buffer = Kernel32.VirtualAllocEx(_processHandle, IntPtr.Zero, size, AllocationType.Commit | AllocationType.Reserve, protectionType);

            if (buffer == IntPtr.Zero)
            {
                throw new Win32Exception($"Failed to call VirtualAllocEx with error code {Marshal.GetLastWin32Error()}");
            }

            return buffer;
        }

        internal void Free(IntPtr baseAddress)
        {
            if (!Kernel32.VirtualFreeEx(_processHandle, baseAddress, 0, FreeType.Release))
            {
                throw new Win32Exception($"Failed to call VirtualFreeEx with error code {Marshal.GetLastWin32Error()}");
            }
        }

        internal void Protect(IntPtr baseAddress, int size, ProtectionType protectionType)
        {
            if (!Kernel32.VirtualProtectEx(_processHandle, baseAddress, size, protectionType, out _))
            {
                throw new Win32Exception($"Failed to call VirtualProtectEx with error code {Marshal.GetLastWin32Error()}");
            }
        }

        internal TStructure Read<TStructure>(IntPtr baseAddress) where TStructure : unmanaged
        {
            return MemoryMarshal.Read<TStructure>(Read(baseAddress, Unsafe.SizeOf<TStructure>()).Span);
        }

        internal Memory<byte> Read(IntPtr baseAddress, int size)
        {
            var buffer = new byte[size];

            if (!Kernel32.ReadProcessMemory(_processHandle, baseAddress, out buffer[0], buffer.Length, IntPtr.Zero))
            {
                throw new Win32Exception($"Failed to call ReadProcessMemory with error code {Marshal.GetLastWin32Error()}");
            }

            return buffer;
        }

        internal void Write(IntPtr baseAddress, Memory<byte> buffer)
        {
            if (!Kernel32.WriteProcessMemory(_processHandle, baseAddress, buffer.Span[0], buffer.Length, IntPtr.Zero))
            {
                throw new Win32Exception($"Failed to call WriteProcessMemory with error code {Marshal.GetLastWin32Error()}");
            }
        }
    }
}