using System.Runtime.InteropServices;
using System.Xml.Linq;
using Lunar.FileResolution.Records;

namespace Lunar.FileResolution;

internal sealed class ActivationContext
{
    private readonly Architecture _architecture;
    private readonly Lazy<ILookup<int, ManifestDirectory>> _directoryCache;
    private readonly XDocument? _manifest;

    internal ActivationContext(XDocument? manifest, Architecture architecture)
    {
        _architecture = architecture;
        _directoryCache = new Lazy<ILookup<int, ManifestDirectory>>(() => GetManifestDirectories(architecture).ToLookup(directory => directory.Hash));
        _manifest = manifest;
    }

    internal string? ProbeManifest(string fileName)
    {
        if (_manifest?.Root is null)
        {
            return null;
        }

        // Build the manifest tree that holds the dependency references

        var @namespace = _manifest.Root.GetDefaultNamespace();
        var elementName1 = @namespace + "dependency";
        var elementName2 = @namespace + "dependentAssembly";
        var elementName3 = @namespace + "assemblyIdentity";

        foreach (var dependency in _manifest.Descendants(elementName1).Elements(elementName2).Elements(elementName3))
        {
            // Parse the dependency attributes

            var architecture = dependency.Attribute("processorArchitecture")?.Value;
            var language = dependency.Attribute("language")?.Value;
            var name = dependency.Attribute("name")?.Value;
            var token = dependency.Attribute("publicKeyToken")?.Value;
            var version = dependency.Attribute("version")?.Value;

            if (architecture is null || language is null || name is null || token is null || version is null)
            {
                continue;
            }

            if (architecture == "*")
            {
                architecture = _architecture == Architecture.X86 ? "x86" : "amd64";
            }

            if (language == "*")
            {
                language = "none";
            }

            // Create a hash for the dependency using the architecture, name and token

            var dependencyHash = $"{architecture}{name.ToLower()}{token}".GetHashCode();

            // Query the cache for a matching list of directories

            if (!_directoryCache.Value.Contains(dependencyHash))
            {
                continue;
            }

            var matchingDirectories = _directoryCache.Value[dependencyHash].Where(directory => directory.Language.Equals(language, StringComparison.OrdinalIgnoreCase));

            // Search for the directory that holds the dependency

            var dependencyVersion = new Version(version);

            ManifestDirectory? matchingDirectory;

            if (dependencyVersion.Build == 0 && dependencyVersion.Revision == 0)
            {
                matchingDirectory = matchingDirectories.Where(directory => directory.Version.Major == dependencyVersion.Major && directory.Version.Minor == dependencyVersion.Minor).OrderByDescending(directory => directory.Version).FirstOrDefault();
            }

            else
            {
                matchingDirectory = matchingDirectories.FirstOrDefault(directory => directory.Version == dependencyVersion);
            }

            if (matchingDirectory is null)
            {
                continue;
            }

            var sxsFilePath = Path.Combine(matchingDirectory.Path, fileName);

            if (File.Exists(sxsFilePath))
            {
                return sxsFilePath;
            }
        }

        return null;
    }

    private static IEnumerable<ManifestDirectory> GetManifestDirectories(Architecture architecture)
    {
        var sxsDirectory = new DirectoryInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS"));
        var directoryPrefix = architecture == Architecture.X86 ? "x86" : "amd64";

        foreach (var directory in sxsDirectory.EnumerateDirectories().Where(directory => directory.Name.StartsWith(directoryPrefix)))
        {
            var nameComponents = directory.Name.Split("_");
            var language = nameComponents[^2];
            var version = new Version(nameComponents[^3]);

            // Create a hash for the directory, skipping the version, language and hash

            var directoryHash = string.Join(string.Empty, nameComponents[..^3]).GetHashCode();

            yield return new ManifestDirectory(directoryHash, language, directory.FullName, version);
        }
    }
}