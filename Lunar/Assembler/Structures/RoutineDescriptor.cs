using System;
using System.Collections.Generic;
using System.Linq;

namespace Lunar.Assembler.Structures
{
    internal sealed class RoutineDescriptor
    {
        internal IntPtr Address { get; }

        internal List<dynamic> Parameters { get; }

        internal IntPtr ReturnBuffer { get; }

        internal RoutineDescriptor(IntPtr address, IEnumerable<dynamic> parameters, IntPtr returnBuffer)
        {
            Address = address;

            Parameters = parameters.ToList();

            ReturnBuffer = returnBuffer;
        }
    }
}