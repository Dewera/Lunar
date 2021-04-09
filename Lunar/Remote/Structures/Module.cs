using System;
using Lunar.PortableExecutable;

namespace Lunar.Remote.Structures
{
    internal sealed record Module(IntPtr Address, Lazy<PeImage> PeImage);
}