using System;
using Lunar.PortableExecutable;

namespace Lunar.Remote.Records
{
    internal sealed record Module(IntPtr Address, PeImage PeImage);
}