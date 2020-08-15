using System;
using System.Collections.Generic;
using System.ComponentModel;
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
using Lunar.Pdb.Structures;

namespace Lunar.Pdb
{
    internal sealed class PdbParser
    {
        private readonly IEnumerable<Symbol> _symbols;

        internal PdbParser(string dllFilePath, params string[] symbolNames)
        {
            var pdbFilePath = DownloadPdb(dllFilePath).GetAwaiter().GetResult();

            _symbols = ParseSymbols(pdbFilePath, symbolNames);
        }

        internal int GetSymbolRva(string symbolName)
        {
            return _symbols.First(symbol => symbol.Name.Equals(symbolName, StringComparison.OrdinalIgnoreCase)).Rva;
        }

        private static async Task<string> DownloadPdb(string dllFilePath)
        {
            // Read the PDB data

            using var peReader = new PEReader(new MemoryStream(File.ReadAllBytes(dllFilePath)));

            var codeViewEntry = peReader.ReadDebugDirectory().First(entry => entry.Type == DebugDirectoryEntryType.CodeView);

            var pdbData = peReader.ReadCodeViewDebugDirectoryData(codeViewEntry);

            // Create a directory on disk to cache the PDB

            var directoryFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Lunar", "Dependencies");

            var directoryInfo = Directory.CreateDirectory(directoryFolderPath);

            // Check if the correct version of the PDB is already cached

            var pdbFilePath = Path.Combine(directoryInfo.FullName, $"{pdbData.Path}-{pdbData.Guid:N}.pdb");

            foreach (var file in directoryInfo.EnumerateFiles())
            {
                if (!file.Name.StartsWith(pdbData.Path))
                {
                    continue;
                }

                if (file.FullName.Equals(pdbFilePath))
                {
                    return pdbFilePath;
                }

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

            webClient.DownloadProgressChanged += (sender, eventArgs) =>
            {
                var progress = eventArgs.ProgressPercentage / 2;

                Console.Write($"\rDownloading required files [{pdbData.Path}] - [{new string('=', progress)}{new string(' ', 50 - progress)}] - {eventArgs.ProgressPercentage}%");
            };

            var pdbUri = new Uri($"https://msdl.microsoft.com/download/symbols/{pdbData.Path}/{pdbData.Guid:N}{pdbData.Age}/{pdbData.Path}");

            await webClient.DownloadFileTaskAsync(pdbUri, pdbFilePath);

            return pdbFilePath;
        }

        private static IEnumerable<Symbol> ParseSymbols(string pdbFilePath, IEnumerable<string> symbolNames)
        {
            // Initialise a symbol handler

            Dbghelp.SymSetOptions(SymbolOptions.UndecorateName);

            using var currentProcessHandle = Kernel32.GetCurrentProcess();

            if (!Dbghelp.SymInitialize(currentProcessHandle, null, false))
            {
                throw new Win32Exception();
            }

            try
            {
                const int pseudoDllBaseAddress = 0x1000;

                // Load the symbol table for the PDB into the symbol handler

                var pdbSize = new FileInfo(pdbFilePath).Length;

                var symbolTableAddress = Dbghelp.SymLoadModuleEx(currentProcessHandle, IntPtr.Zero, pdbFilePath, null, pseudoDllBaseAddress, (int) pdbSize, IntPtr.Zero, 0);

                if (symbolTableAddress == 0)
                {
                    throw new Win32Exception();
                }

                foreach (var symbolName in symbolNames)
                {
                    // Initialise a buffer to receive the symbol information

                    var symbolInformationBufferSize = (Unsafe.SizeOf<SymbolInfo>() + Constants.MaxSymbolName * sizeof(char) + sizeof(long) - 1) / sizeof(long);

                    Span<byte> symbolInformationBuffer = stackalloc byte[symbolInformationBufferSize];

                    var symbolInformation = new SymbolInfo(Constants.MaxSymbolName);

                    MemoryMarshal.Write(symbolInformationBuffer, ref symbolInformation);

                    // Retrieve the symbol information

                    if (!Dbghelp.SymFromName(currentProcessHandle, symbolName, out symbolInformationBuffer[0]))
                    {
                        throw new Win32Exception();
                    }

                    // Calculate the relative virtual address of the symbol

                    symbolInformation = MemoryMarshal.Read<SymbolInfo>(symbolInformationBuffer);

                    var symbolRva = symbolInformation.Address - pseudoDllBaseAddress;

                    yield return new Symbol(symbolName, (int) symbolRva);
                }
            }

            finally
            {
                Dbghelp.SymCleanup(currentProcessHandle);
            }
        }
    }
}