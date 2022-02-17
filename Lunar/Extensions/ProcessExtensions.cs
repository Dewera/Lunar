using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Native.Enums;
using Lunar.Native.PInvoke;

namespace Lunar.Extensions;

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

    internal static void FreeBuffer(this Process process, IntPtr address)
    {
        if (!Kernel32.VirtualFreeEx(process.SafeHandle, address, 0, FreeType.Release))
        {
            throw new Win32Exception();
        }
    }

    internal static Architecture GetArchitecture(this Process process)
    {
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

    internal static T QueryInformation<T>(this Process process, ProcessInformationType informationType) where T : unmanaged
    {
        Span<byte> informationBytes = stackalloc byte[Unsafe.SizeOf<T>()];

        var status = Ntdll.NtQueryInformationProcess(process.SafeHandle, informationType, out informationBytes[0], informationBytes.Length, IntPtr.Zero);

        if (status != NtStatus.Success)
        {
            throw new Win32Exception(Ntdll.RtlNtStatusToDosError(status));
        }

        return MemoryMarshal.Read<T>(informationBytes);
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
        return MemoryMarshal.Read<T>(process.ReadSpan<byte>(address, Unsafe.SizeOf<T>()));
    }

    internal static void WriteSpan<T>(this Process process, IntPtr address, Span<T> span) where T : unmanaged
    {
        var spanBytes = MemoryMarshal.AsBytes(span);

        var oldProtectionType = process.ProtectBuffer(address, spanBytes.Length, ProtectionType.ExecuteReadWrite);

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
        process.WriteSpan(address, Encoding.Unicode.GetBytes(@string).AsSpan());
    }

    internal static void WriteStruct<T>(this Process process, IntPtr address, T @struct) where T : unmanaged
    {
        process.WriteSpan(address, MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref @struct, 1)));
    }
}