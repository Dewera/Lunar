using System;
using System.Collections.Generic;
using System.Linq;

namespace Lunar.Assembler.Structures
{
    internal sealed class RoutineDescriptor
    {
        internal IntPtr Address { get; }

        internal List<dynamic> Parameters { get; }

        internal IntPtr ReturnValueBuffer { get; }

        internal RoutineDescriptor(IntPtr address, IEnumerable<dynamic> parameters, IntPtr returnValueBuffer)
        {
            Address = address;

            Parameters = parameters.ToList();

            ReturnValueBuffer = returnValueBuffer;
        }
    }
}