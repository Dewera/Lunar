using System;
using System.Runtime.InteropServices;

namespace Lunar.FunctionCall.Structures
{
    internal sealed class CallDescriptor
    {
        internal IntPtr Address { get; }

        internal CallingConvention CallingConvention { get; }

        internal bool IsWow64Call { get; }

        internal long[] Parameters { get; }

        internal IntPtr ReturnAddress { get; }

        internal CallDescriptor(IntPtr address, CallingConvention callingConvention, bool isWow64Call, long[] parameters, IntPtr returnAddress)
        {
            Address = address;

            CallingConvention = callingConvention;

            IsWow64Call = isWow64Call;

            Parameters = parameters;

            ReturnAddress = returnAddress;
        }
    }
}