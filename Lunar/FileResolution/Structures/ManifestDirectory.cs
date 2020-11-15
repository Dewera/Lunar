using System;

namespace Lunar.FileResolution.Structures
{
    internal sealed record ManifestDirectory(int Hash, string Language, string Path, Version Version);
}