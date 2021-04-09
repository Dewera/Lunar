using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
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
            // Check for .local redirection

            var dotLocalFilePath = Path.Combine(_process.MainModule!.FileName!, ".local", fileName);

            if (File.Exists(dotLocalFilePath))
            {
                return dotLocalFilePath;
            }

            // Check for SxS redirection

            var sxsFilePath = activationContext.ProbeManifest(fileName);

            if (sxsFilePath is not null)
            {
                return sxsFilePath;
            }

            // Search the root directory of the DLL

            if (_rootDirectoryPath is not null)
            {
                var rootDirectoryFilePath = Path.Combine(_rootDirectoryPath, fileName);

                if (File.Exists(rootDirectoryFilePath))
                {
                    return rootDirectoryFilePath;
                }
            }

            // Search the directory from which the process was loaded

            var processDirectoryFilePath = Path.Combine(_process.MainModule!.FileName!, fileName);

            if (File.Exists(processDirectoryFilePath))
            {
                return processDirectoryFilePath;
            }

            // Search the System directory

            var systemDirectoryPath = _process.GetArchitecture() == Architecture.X86 ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) : Environment.SystemDirectory;

            var systemDirectoryFilePath = Path.Combine(systemDirectoryPath, fileName);

            if (File.Exists(systemDirectoryFilePath))
            {
                return systemDirectoryFilePath;
            }

            // Search the Windows directory

            var windowsDirectoryFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), fileName);

            if (File.Exists(windowsDirectoryFilePath))
            {
                return windowsDirectoryFilePath;
            }

            // Search the current directory

            var currentDirectoryFilePath = Path.Combine(Directory.GetCurrentDirectory(), fileName);

            if (File.Exists(currentDirectoryFilePath))
            {
                return currentDirectoryFilePath;
            }

            // Search the directories listed in the PATH environment variable

            var path = Environment.GetEnvironmentVariable("PATH");

            return path?.Split(";").Where(Directory.Exists).Select(directory => Path.Combine(directory, fileName)).FirstOrDefault(File.Exists);
        }
    }
}