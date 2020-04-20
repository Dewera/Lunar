using System;
using System.Runtime.InteropServices;

namespace Lunar.RoutineCall.Structures
{
    internal sealed class RoutineDescriptor
    {
        internal Architecture Architecture { get; }

        internal CallingConvention CallingConvention { get; }

        internal IntPtr FunctionAddress { get; }

        internal long[] Parameters { get; }

        internal IntPtr ReturnBuffer { get; }

        internal RoutineDescriptor(Architecture architecture, CallingConvention callingConvention, IntPtr functionAddress, long[] parameters, IntPtr returnBuffer)
        {
            Architecture = architecture;

            CallingConvention = callingConvention;

            FunctionAddress = functionAddress;

            Parameters = parameters;

            ReturnBuffer = returnBuffer;
        }
    }
}