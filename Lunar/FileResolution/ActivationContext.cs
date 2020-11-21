using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Xml.Linq;
using Lunar.Extensions;
using Lunar.FileResolution.Structures;

namespace Lunar.FileResolution
{
    internal sealed class ActivationContext
    {
        private readonly ILookup<int, ManifestDirectory> _directoryCache;

        private readonly XDocument? _manifest;

        private readonly Process _process;

        internal ActivationContext(XDocument? manifest, Process process)
        {
            _directoryCache = GetManifestDirectories(process).ToLookup(directory => directory.Hash);

            _manifest = manifest;

            _process = process;
        }

        internal string? ProbeManifest(string fileName)
        {
            if (_manifest?.Root is null)
            {
                return null;
            }

            var @namespace = _manifest.Root.GetDefaultNamespace();

            foreach (var dependency in _manifest.Descendants(@namespace + "dependency").Elements(@namespace + "dependentAssembly").Elements(@namespace + "assemblyIdentity"))
            {
                // Parse the attributes of the dependency

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
                    architecture = _process.GetArchitecture() == Architecture.X86 ? "x86" : "amd64";
                }

                if (language == "*")
                {
                    language = "none";
                }

                // Create a hash for the dependency using the architecture, name and token

                var dependencyHash = string.Join(string.Empty, architecture, name.ToLower(), token).GetHashCode();

                // Query the cache for a matching list of directories

                if (!_directoryCache.Contains(dependencyHash))
                {
                    continue;
                }

                var matchingDirectories = _directoryCache[dependencyHash].Where(directory => directory.Language.Equals(language, StringComparison.OrdinalIgnoreCase));

                // Look for the directory that holds the dependency

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

        private static IEnumerable<ManifestDirectory> GetManifestDirectories(Process process)
        {
            var architecture = process.GetArchitecture() == Architecture.X86 ? "x86" : "amd64";

            var sxsDirectory = new DirectoryInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS"));

            foreach (var directory in sxsDirectory.EnumerateDirectories().Where(directory => directory.Name.StartsWith(architecture)))
            {
                var nameComponents = directory.Name.Split("_");

                var language = nameComponents[^2];

                var version = new Version(nameComponents[^3]);

                // Create a hash for the directory name, skipping the version, language and hash

                var nameHash = string.Join(string.Empty, nameComponents[..^3]).GetHashCode();

                yield return new ManifestDirectory(nameHash, language, directory.FullName, version);
            }
        }
    }
}