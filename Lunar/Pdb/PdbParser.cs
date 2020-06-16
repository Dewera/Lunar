using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Lunar.Native;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Lunar.Native.Structures;
using Lunar.Pdb.Structures;
using Lunar.PortableExecutable;

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

        internal Symbol GetSymbol(string symbolName)
        {
            return _symbols.First(symbol => symbol.Name.Equals(symbolName, StringComparison.OrdinalIgnoreCase));
        }

        private static async Task<string> DownloadPdb(string dllFilePath)
        {
            var peImage = new PeImage(File.ReadAllBytes(dllFilePath));

            // Create a directory on disk to cache the PDB

            var directoryFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Lunar", "Dependencies");

            var directoryInfo = Directory.CreateDirectory(directoryFolderPath);

            // Check if the correct version of the PDB is already cached

            var pdbFilePath = Path.Combine(directoryInfo.FullName, $"{peImage.PdbData.Path}-{peImage.PdbData.Guid:N}.pdb");

            foreach (var file in directoryInfo.EnumerateFiles())
            {
                if (!file.Name.StartsWith(peImage.PdbData.Path))
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

                Console.Write($"\rDownloading required files [{peImage.PdbData.Path}] - [{new string('=', progress)}{new string(' ', 50 - progress)}] - {eventArgs.ProgressPercentage}%");
            };

            var pdbUri = new Uri($"https://msdl.microsoft.com/download/symbols/{peImage.PdbData.Path}/{peImage.PdbData.Guid:N}{peImage.PdbData.Age}/{peImage.PdbData.Path}");

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
                // Load the symbol table for the PDB into the symbol handler

                const int pseudoDllBaseAddress = 0x1000;

                var pdbSize = new FileInfo(pdbFilePath).Length;

                var symbolTableAddress = Dbghelp.SymLoadModuleEx(currentProcessHandle, IntPtr.Zero, pdbFilePath, null, pseudoDllBaseAddress, (int) pdbSize, IntPtr.Zero, 0);

                if (symbolTableAddress == 0)
                {
                    throw new Win32Exception();
                }

                var symbolInformationBlockSize = (Unsafe.SizeOf<SymbolInfo>() + Constants.MaxSymbolName * sizeof(char) + sizeof(long) - 1) / sizeof(long);

                int GetSymbolRva(string symbolName)
                {
                    // Initialise a block to receive the symbol information

                    Span<byte> symbolInformationBlock = stackalloc byte[symbolInformationBlockSize];

                    var symbolInformation = new SymbolInfo(Constants.MaxSymbolName);

                    MemoryMarshal.Write(symbolInformationBlock, ref symbolInformation);

                    // Retrieve the symbol information

                    if (!Dbghelp.SymFromName(currentProcessHandle, symbolName, out symbolInformationBlock[0]))
                    {
                        throw new Win32Exception();
                    }

                    // Calculate the relative virtual address of the symbol

                    symbolInformation = MemoryMarshal.Read<SymbolInfo>(symbolInformationBlock);

                    return (int) (symbolInformation.Address - pseudoDllBaseAddress);
                }

                foreach (var symbolName in symbolNames)
                {
                    var symbolRva = GetSymbolRva(symbolName);

                    yield return new Symbol(symbolName, symbolRva);
                }
            }

            finally
            {
                Dbghelp.SymCleanup(currentProcessHandle);
            }
        }
    }
}