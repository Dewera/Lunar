using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Lunar.Extensions;

namespace Lunar.FileResolution
{
    internal sealed class FileResolver
    {
        private readonly Process _process;

        private readonly string? _rootDirectoryPath;

        internal FileResolver(Process process, string? rootDirectoryPath)
        {
            _process = process;

            _rootDirectoryPath = rootDirectoryPath;
        }

        internal string? ResolveFilePath(ActivationContext activationContext, string fileName)
        {
            // Search the manifest

            var sxsFilePath = activationContext.ProbeManifest(fileName);

            if (sxsFilePath is not null)
            {
                return sxsFilePath;
            }

            // Search the root directory

            if (_rootDirectoryPath is not null)
            {
                var rootFilePath = Path.Combine(_rootDirectoryPath, fileName);

                if (File.Exists(rootFilePath))
                {
                    return rootFilePath;
                }
            }

            // Search the System directory

            var systemFilePath = Path.Combine(_process.GetSystemDirectoryPath(), fileName);

            if (File.Exists(systemFilePath))
            {
                return systemFilePath;
            }

            // Search the Windows directory

            var windowsFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), fileName);

            if (File.Exists(windowsFilePath))
            {
                return windowsFilePath;
            }

            // Search the current directory

            var currentFilePath = Path.Combine(Directory.GetCurrentDirectory(), fileName);

            if (File.Exists(currentFilePath))
            {
                return currentFilePath;
            }

            // Search the directories listed in the PATH environment variable

            var path = Environment.GetEnvironmentVariable("PATH");

            return path?.Split(";").Where(Directory.Exists).Select(directory => Path.Combine(directory, fileName)).FirstOrDefault(File.Exists);
        }
    }
}