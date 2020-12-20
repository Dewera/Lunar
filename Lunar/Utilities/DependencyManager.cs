using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Threading.Tasks;
using Lunar.Extensions;

namespace Lunar.Utilities
{
    internal static class DependencyManager
    {
        internal static async Task<string> FindOrDownloadNtdllPdb(Process process)
        {
            var ntdllFilePath = Path.Combine(process.GetSystemDirectoryPath(), "ntdll.dll");

            // Read the PDB data

            using var peReader = new PEReader(File.OpenRead(ntdllFilePath));

            var codeViewEntry = peReader.ReadDebugDirectory().First(entry => entry.Type == DebugDirectoryEntryType.CodeView);

            var pdbData = peReader.ReadCodeViewDebugDirectoryData(codeViewEntry);

            // Find or create the cache directory

            var cacheDirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Lunar", "Dependencies");

            var cacheDirectory = Directory.CreateDirectory(cacheDirectoryPath);

            // Check if the correct version of the PDB is already cached

            var pdbFilePath = Path.Combine(cacheDirectory.FullName, $"{pdbData.Path}-{pdbData.Guid:N}.pdb");

            if (File.Exists(pdbFilePath))
            {
                return pdbFilePath;
            }

            // Clear the directory of any old PDB versions

            foreach (var file in cacheDirectory.EnumerateFiles().Where(file => file.Name.StartsWith(pdbData.Path)))
            {
                try
                {
                    file.Delete();
                }

                catch (IOException)
                {
                    // The file cannot be safely deleted
                }
            }

            // Download the PDB from the Microsoft symbol server

            using var webClient = new WebClient();

            webClient.DownloadProgressChanged += (_, eventArguments) =>
            {
                var progress = eventArguments.ProgressPercentage / 2;

                Console.Write($"\rDownloading required files [{pdbData.Path}] - [{new string('=', progress)}{new string(' ', 50 - progress)}] - {eventArguments.ProgressPercentage}%");
            };

            await webClient.DownloadFileTaskAsync(new Uri($"https://msdl.microsoft.com/download/symbols/{pdbData.Path}/{pdbData.Guid:N}{pdbData.Age}/{pdbData.Path}"), pdbFilePath);

            return pdbFilePath;
        }
    }
}