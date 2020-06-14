using System;
using System.Collections.Generic;
using System.IO;
using Lunar.PortableExecutable;
using Lunar.PortableExecutable.Structures;

namespace Lunar.RemoteProcess.Structures
{
    internal sealed class Module
    {
        internal IntPtr Address { get; }

        internal Lazy<IEnumerable<ExportedFunction>> ExportedFunctions { get; }

        internal string Name { get; }

        internal Module(IntPtr address, string filePath, string name)
        {
            Address = address;

            ExportedFunctions = new Lazy<IEnumerable<ExportedFunction>>(() => new PeImage(File.ReadAllBytes(filePath)).ExportDirectory.ExportedFunctions);

            Name = name;
        }
    }
}