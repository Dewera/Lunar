using System;
using System.Runtime.InteropServices;

namespace Lunar.Shared
{
    internal static class SafeHelpers
    {
        internal static IntPtr CreateSafeIntPtr(int pointer)
        {
            if (pointer >= 0)
            {
                return new IntPtr(pointer);
            }

            Span<byte> pointerBuffer = stackalloc byte[IntPtr.Size];

            MemoryMarshal.Write(pointerBuffer, ref pointer);

            return MemoryMarshal.Read<IntPtr>(pointerBuffer);
        }

        internal static IntPtr CreateSafeIntPtr(long pointer)
        {
            if (pointer >= 0)
            {
                return new IntPtr(pointer);
            }

            Span<byte> pointerBuffer = stackalloc byte[IntPtr.Size];

            MemoryMarshal.Write(pointerBuffer, ref pointer);

            return MemoryMarshal.Read<IntPtr>(pointerBuffer);
        }
    }
}