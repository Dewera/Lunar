using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Lunar.Native;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Lunar.Native.Structures;
using Lunar.PortableExecutable;
using Lunar.Shared;

namespace Lunar.Symbol
{
    internal sealed class SymbolParser
    {
        internal ImmutableDictionary<string, int> SymbolOffsets { get; }
        
        internal SymbolParser(string dllFilePath, params string[] symbolNames)
        {
            var pdbPath = DownloadPdb(dllFilePath).Result;

            SymbolOffsets = ParseSymbolOffsets(pdbPath, symbolNames);
        }

        private static async Task<string> DownloadPdb(string dllFilePath)
        {
            // Retrieve the code view debug data for the DLL
            
            var peImage = new PeImage(File.ReadAllBytes(dllFilePath));

            var codeViewDebugDirectoryData = peImage.CodeViewDebugDirectoryData;

            // Ensure a directory exists to cache the PDB
            
            var applicationDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
  
            var directoryPath = Path.Combine(applicationDataPath, "Lunar", "Dependencies");
              
            var directoryInfo = Directory.CreateDirectory(directoryPath);

            // Determine if the correct version of the PDB is already on disk

            var pdbPath = Path.Combine(directoryInfo.FullName, $"{codeViewDebugDirectoryData.Path}-{codeViewDebugDirectoryData.Guid:N}.pdb");
            
            foreach (var file in directoryInfo.EnumerateFiles())
            {
                if (!file.Name.StartsWith(codeViewDebugDirectoryData.Path))
                {
                    continue;
                }
                
                if (file.FullName.Equals(pdbPath))
                {
                    return pdbPath;
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
            
            var pdbUri = $"https://msdl.microsoft.com/download/symbols/{codeViewDebugDirectoryData.Path}/{codeViewDebugDirectoryData.Guid:N}{codeViewDebugDirectoryData.Age}/{codeViewDebugDirectoryData.Path}";
              
            using var webClient = new WebClient();
  
            await webClient.DownloadFileTaskAsync(pdbUri, pdbPath);

            return pdbPath;
        }

        private static ImmutableDictionary<string, int> ParseSymbolOffsets(string pdbPath, IEnumerable<string> symbolNames)
        {
            var symbolOffsets = new Dictionary<string, int>();
            
            using var localProcess = Process.GetCurrentProcess();
            
            // Initialise a symbol handler
            
            Dbghelp.SymSetOptions(SymbolOptions.UndecorateName | SymbolOptions.DeferredLoads);

            if (!Dbghelp.SymInitialize(localProcess.SafeHandle, null, false))
            {
                throw ExceptionBuilder.BuildWin32Exception("SymInitialize");
            }
            
            // Load the symbol table for the PDB
            
            const int pseudoDllBaseAddress = 0x1000;
            
            var pdbSize = new FileInfo(pdbPath).Length;
            
            var symbolTableAddress = Dbghelp.SymLoadModuleEx(localProcess.SafeHandle, IntPtr.Zero, pdbPath, null, pseudoDllBaseAddress, (int) pdbSize, IntPtr.Zero, 0);

            if (symbolTableAddress == 0)
            {
                throw ExceptionBuilder.BuildWin32Exception("SymLoadModuleEx");
            }
            
            // Initialise a buffer to receive the symbol information
            
            var symbolInfoBufferSize = (Unsafe.SizeOf<SymbolInfo>() + Constants.MaxSymbolName * sizeof(char) + sizeof(long) - 1) / sizeof(long);

            var symbolInfoBuffer = new byte[symbolInfoBufferSize];

            var symbolInfo = new SymbolInfo(Constants.MaxSymbolName);
            
            MemoryMarshal.Write(symbolInfoBuffer, ref symbolInfo);
            
            // Retrieve the offsets of the symbols

            SymbolInfo RetrieveSymbolInformation(string symbolName)
            {
                if (!Dbghelp.SymFromName(localProcess.SafeHandle, symbolName, ref symbolInfoBuffer[0]))
                {
                    throw ExceptionBuilder.BuildWin32Exception("SymFromName");
                }
                
                return MemoryMarshal.Read<SymbolInfo>(symbolInfoBuffer);
            }

            foreach (var symbolName in symbolNames)
            {
                var symbolInformation = RetrieveSymbolInformation(symbolName);
                
                symbolOffsets.Add(symbolName, (int) (symbolInformation.Address - pseudoDllBaseAddress));
            }

            if (!Dbghelp.SymCleanup(localProcess.SafeHandle))
            {
                throw ExceptionBuilder.BuildWin32Exception("SymCleanup");
            }
            
            return symbolOffsets.ToImmutableDictionary();
        }
    }
}