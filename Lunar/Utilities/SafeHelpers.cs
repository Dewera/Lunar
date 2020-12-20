using System;
using System.Runtime.CompilerServices;

namespace Lunar.Utilities
{
    internal static class SafeHelpers
    {
        internal static IntPtr CreateSafePointer(int pointer)
        {
            return pointer >= 0 ? new IntPtr(pointer) : Unsafe.As<int, IntPtr>(ref pointer);
        }

        internal static IntPtr CreateSafePointer(long pointer)
        {
            return pointer >= 0 ? new IntPtr(pointer) : Unsafe.As<long, IntPtr>(ref pointer);
        }
    }
}