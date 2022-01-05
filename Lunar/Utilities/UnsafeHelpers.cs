using System.Runtime.CompilerServices;

namespace Lunar.Utilities;

internal static class UnsafeHelpers
{
    internal static IntPtr WrapPointer(int pointer)
    {
        return pointer >= 0 ? new IntPtr(pointer) : Unsafe.As<int, IntPtr>(ref pointer);
    }

    internal static IntPtr WrapPointer(long pointer)
    {
        return pointer >= 0 ? new IntPtr(pointer) : Unsafe.As<long, IntPtr>(ref pointer);
    }
}