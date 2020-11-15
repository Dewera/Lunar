using System;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Lunar.Native;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Lunar.Native.Structures;

namespace Lunar.Symbol
{
    internal sealed class SymbolHandler
    {
        private readonly string _pdbFilePath;

        internal SymbolHandler(string dllFilePath)
        {
            _pdbFilePath = FindOrDownloadPdb(dllFilePath).GetAwaiter().GetResult();
        }

        internal int GetSymbolAddress(string symbolName)
        {
            // Initialise a symbol handler

            Dbghelp.SymSetOptions(SymbolOptions.UndecorateName);

            using var currentProcessHandle = Process.GetCurrentProcess().SafeHandle;

            if (!Dbghelp.SymInitialize(currentProcessHandle, null, false))
            {
                throw new Win32Exception();
            }

            try
            {
                const int pseudoDllAddress = 0x1000;

                // Load the symbol table for the PDB into the symbol handler

                var pdbSize = new FileInfo(_pdbFilePath).Length;

                var symbolTableAddress = Dbghelp.SymLoadModule(currentProcessHandle, IntPtr.Zero, _pdbFilePath, null, pseudoDllAddress, (int) pdbSize);

                if (symbolTableAddress == 0)
                {
                    throw new Win32Exception();
                }

                // Initialise an array to receive the symbol information

                var symbolInformationSize = (Unsafe.SizeOf<SymbolInfo>() + sizeof(char) * Constants.MaxSymbolNameLength + sizeof(long) - 1) / sizeof(long);

                Span<byte> symbolInformationBytes = stackalloc byte[symbolInformationSize];

                MemoryMarshal.Write(symbolInformationBytes, ref Unsafe.AsRef(new SymbolInfo(Constants.MaxSymbolNameLength)));

                // Retrieve the symbol information

                if (!Dbghelp.SymFromName(currentProcessHandle, symbolName, out symbolInformationBytes[0]))
                {
                    throw new Win32Exception();
                }

                // Calculate the address of the symbol

                var symbolInformation = MemoryMarshal.Read<SymbolInfo>(symbolInformationBytes);

                return (int) symbolInformation.Address - pseudoDllAddress;
            }

            finally
            {
                Dbghelp.SymCleanup(currentProcessHandle);
            }
        }

        private static async Task<string> FindOrDownloadPdb(string dllFilePath)
        {
            // Read the PDB data

            using var peReader = new PEReader(File.ReadAllBytes(dllFilePath).ToImmutableArray());

            var codeViewEntry = peReader.ReadDebugDirectory().First(entry => entry.Type == DebugDirectoryEntryType.CodeView);

            var pdbData = peReader.ReadCodeViewDebugDirectoryData(codeViewEntry);

            // Find or create the PDB cache directory

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

            webClient.DownloadProgressChanged += (_, eventArgs) =>
            {
                var progress = eventArgs.ProgressPercentage / 2;

                Console.Write($"\rDownloading required files [{pdbData.Path}] - [{new string('=', progress)}{new string(' ', 50 - progress)}] - {eventArgs.ProgressPercentage}%");
            };

            var pdbUri = new Uri($"https://msdl.microsoft.com/download/symbols/{pdbData.Path}/{pdbData.Guid:N}{pdbData.Age}/{pdbData.Path}");

            await webClient.DownloadFileTaskAsync(pdbUri, pdbFilePath);

            return pdbFilePath;
        }
    }
}