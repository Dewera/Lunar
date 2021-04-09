using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Remote
{
    internal sealed class Memory
    {
        private readonly SafeProcessHandle _processHandle;

        internal Memory(SafeProcessHandle processHandle)
        {
            _processHandle = processHandle;
        }

        internal IntPtr AllocateBuffer(int size, ProtectionType protectionType)
        {
            var address = Kernel32.VirtualAllocEx(_processHandle, IntPtr.Zero, size, AllocationType.Commit | AllocationType.Reserve, protectionType);

            if (address == IntPtr.Zero)
            {
                throw new Win32Exception();
            }

            return address;
        }

        internal void FreeBuffer(IntPtr address)
        {
            if (!Kernel32.VirtualFreeEx(_processHandle, address, 0, FreeType.Release))
            {
                throw new Win32Exception();
            }
        }

        internal ProtectionType ProtectBuffer(IntPtr address, int size, ProtectionType protectionType)
        {
            if (!Kernel32.VirtualProtectEx(_processHandle, address, size, protectionType, out var oldProtectionType))
            {
                throw new Win32Exception();
            }

            return oldProtectionType;
        }

        internal Span<T> ReadSpan<T>(IntPtr address, int elements) where T : unmanaged
        {
            var spanBytes = new byte[Unsafe.SizeOf<T>() * elements];

            if (!Kernel32.ReadProcessMemory(_processHandle, address, out spanBytes[0], spanBytes.Length, IntPtr.Zero))
            {
                throw new Win32Exception();
            }

            return MemoryMarshal.Cast<byte, T>(spanBytes);
        }

        internal T ReadStructure<T>(IntPtr address) where T : unmanaged
        {
            Span<byte> structureBytes = stackalloc byte[Unsafe.SizeOf<T>()];

            if (!Kernel32.ReadProcessMemory(_processHandle, address, out structureBytes[0], structureBytes.Length, IntPtr.Zero))
            {
                throw new Win32Exception();
            }

            return MemoryMarshal.Read<T>(structureBytes);
        }

        internal void WriteSpan<T>(IntPtr address, Span<T> span) where T : unmanaged
        {
            var spanBytes = MemoryMarshal.AsBytes(span);

            var oldProtectionType = ProtectBuffer(address, spanBytes.Length, ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(_processHandle, address, in spanBytes[0], spanBytes.Length, IntPtr.Zero))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                ProtectBuffer(address, spanBytes.Length, oldProtectionType);
            }
        }

        internal void WriteString(IntPtr address, string @string)
        {
            var stringBytes = Encoding.Unicode.GetBytes(@string);

            var oldProtectionType = ProtectBuffer(address, stringBytes.Length, ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(_processHandle, address, in stringBytes[0], stringBytes.Length, IntPtr.Zero))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                ProtectBuffer(address, stringBytes.Length, oldProtectionType);
            }
        }

        internal void WriteStructure<T>(IntPtr address, T structure) where T : unmanaged
        {
            Span<byte> structureBytes = stackalloc byte[Unsafe.SizeOf<T>()];

            MemoryMarshal.Write(structureBytes, ref structure);

            var oldProtectionType = ProtectBuffer(address, structureBytes.Length, ProtectionType.ReadWrite);

            try
            {
                if (!Kernel32.WriteProcessMemory(_processHandle, address, in structureBytes[0], structureBytes.Length, IntPtr.Zero))
                {
                    throw new Win32Exception();
                }
            }

            finally
            {
                ProtectBuffer(address, structureBytes.Length, oldProtectionType);
            }
        }
    }
}