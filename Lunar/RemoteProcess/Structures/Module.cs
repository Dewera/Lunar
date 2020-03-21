using System;
using System.IO;
using Lunar.PortableExecutable;

namespace Lunar.RemoteProcess.Structures
{
    internal sealed class Module
    {
        internal IntPtr BaseAddress { get; }

        internal string Name { get; }

        internal Lazy<PeImage> PeImage { get; }

        internal Module(IntPtr baseAddress, string name, string filePath)
        {
            BaseAddress = baseAddress;

            Name = name;

            PeImage = new Lazy<PeImage>(() => new PeImage(File.ReadAllBytes(filePath)));
        }
    }
}