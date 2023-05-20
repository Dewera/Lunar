using System.Diagnostics;
using System.Runtime.InteropServices;
using Lunar.Extensions;

namespace Lunar.FileResolution;

internal sealed class FileResolver
{
    private readonly Architecture _architecture;
    private readonly string _processDirectoryPath;
    private readonly string? _rootDirectoryPath;

    internal FileResolver(Process process, string? rootDirectoryPath)
    {
        _architecture = process.GetArchitecture();
        _processDirectoryPath = Path.GetDirectoryName(process.MainModule!.FileName)!;
        _rootDirectoryPath = rootDirectoryPath;
    }

    internal string? ResolveFilePath(string fileName, ActivationContext activationContext)
    {
        // Check for .local redirection

        var dotLocalFilePath = Path.Combine(_processDirectoryPath, ".local", fileName);

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

        // Search the DLL root directory

        if (_rootDirectoryPath is not null)
        {
            var rootDirectoryFilePath = Path.Combine(_rootDirectoryPath, fileName);

            if (File.Exists(rootDirectoryFilePath))
            {
                return rootDirectoryFilePath;
            }
        }

        // Search the directory from which the process was loaded

        var processDirectoryFilePath = Path.Combine(_processDirectoryPath, fileName);

        if (File.Exists(processDirectoryFilePath))
        {
            return processDirectoryFilePath;
        }

        // Search the System directory

        var systemDirectoryPath = _architecture == Architecture.X86 ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) : Environment.SystemDirectory;
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