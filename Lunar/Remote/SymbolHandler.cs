using System.ComponentModel;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native;
using Lunar.Native.Enums;
using Lunar.Native.PInvoke;
using Lunar.Native.Structs;
using Lunar.Remote.Records;
using Microsoft.Win32.SafeHandles;

namespace Lunar.Remote;

internal sealed class SymbolHandler
{
    private readonly string _pdbFilePath;
    private readonly IDictionary<string, Symbol> _symbolCache;

    internal SymbolHandler(Architecture architecture)
    {
        _pdbFilePath = FindOrDownloadSymbolFile(architecture);
        _symbolCache = new Dictionary<string, Symbol>();
    }

    internal Symbol GetSymbol(string symbolName)
    {
        if (_symbolCache.TryGetValue(symbolName, out var symbol))
        {
            return symbol;
        }

        var currentProcessHandle = new SafeProcessHandle(-1, false);

        // Initialise a native symbol handler

        if (!Dbghelp.SymSetOptions(SymbolOptions.UndecorateName).HasFlag(SymbolOptions.UndecorateName))
        {
            throw new Win32Exception();
        }

        if (!Dbghelp.SymInitialize(currentProcessHandle, 0, false))
        {
            throw new Win32Exception();
        }

        try
        {
            // Load the PDB into the symbol handler

            const int pseudoDllAddress = 0x1000;

            var pdbFileSize = new FileInfo(_pdbFilePath).Length;
            var symbolTableAddress = Dbghelp.SymLoadModule(currentProcessHandle, 0, _pdbFilePath, 0, pseudoDllAddress, (int) pdbFileSize, 0, 0);

            if (symbolTableAddress == 0)
            {
                throw new Win32Exception();
            }

            // Initialise a buffer to store the symbol information

            var symbolInformationBytes = (stackalloc byte[(Unsafe.SizeOf<SymbolInfo>() + sizeof(char) * Constants.MaxSymbolName + sizeof(long) - 1) / sizeof(long)]);
            MemoryMarshal.Write(symbolInformationBytes, ref Unsafe.AsRef(new SymbolInfo(Unsafe.SizeOf<SymbolInfo>(), 0, Constants.MaxSymbolName)));

            // Retrieve the symbol information

            if (!Dbghelp.SymFromName(currentProcessHandle, symbolName, out Unsafe.As<byte, SymbolInfo>(ref symbolInformationBytes[0])))
            {
                throw new Win32Exception();
            }

            var symbolInformation = MemoryMarshal.Read<SymbolInfo>(symbolInformationBytes);
            symbol = new Symbol((int) (symbolInformation.Address - pseudoDllAddress));
            _symbolCache.Add(symbolName, symbol);

            return symbol;
        }
        finally
        {
            Dbghelp.SymCleanup(currentProcessHandle);
        }
    }

    private static string FindOrDownloadSymbolFile(Architecture architecture)
    {
        // Read the ntdll.dll PDB data

        var systemDirectoryPath = architecture == Architecture.X86 ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) : Environment.SystemDirectory;
        var ntdllFilePath = Path.Combine(systemDirectoryPath, "ntdll.dll");

        using var peReader = new PEReader(File.OpenRead(ntdllFilePath));
        var codeViewEntry = peReader.ReadDebugDirectory().First(entry => entry.Type == DebugDirectoryEntryType.CodeView);
        var pdbData = peReader.ReadCodeViewDebugDirectoryData(codeViewEntry);

        // Find or create the cache directory

        var cacheDirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Lunar", "Dependencies");
        var cacheDirectory = Directory.CreateDirectory(cacheDirectoryPath);

        // Check if the correct PDB version is already cached

        var pdbFilePath = Path.Combine(cacheDirectory.FullName, $"{pdbData.Path.Replace(".pdb", string.Empty)}-{pdbData.Guid:N}.pdb");
        var pdbFile = new FileInfo(pdbFilePath);

        if (pdbFile.Exists && pdbFile.Length != 0)
        {
            return pdbFilePath;
        }

        // Delete any old PDB versions

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

        using var httpClient = new HttpClient();
        using var response = httpClient.GetAsync(new Uri($"https://msdl.microsoft.com/download/symbols/{pdbData.Path}/{pdbData.Guid:N}{pdbData.Age}/{pdbData.Path}"), HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Failed to download required files [{pdbData.Path}] with status code {response.StatusCode}");
        }

        if (response.Content.Headers.ContentLength is null)
        {
            throw new HttpRequestException($"Failed to retrieve content headers for required files [{pdbData.Path}]");
        }

        using var contentStream = response.Content.ReadAsStream();
        using var fileStream = new FileStream(pdbFilePath, FileMode.Create);

        var copyBuffer = new byte[65536];
        var bytesRead = 0d;

        while (true)
        {
            var blockSize = contentStream.Read(copyBuffer);

            if (blockSize == 0)
            {
                break;
            }

            bytesRead += blockSize;

            var progressPercentage = bytesRead / response.Content.Headers.ContentLength.Value * 100;
            var progress = progressPercentage / 2;
            Console.Write($"\rDownloading required files [{pdbData.Path}] - [{new string('=', (int) progress)}{new string(' ', 50 - (int) progress)}] - {(int) progressPercentage}%");

            fileStream.Write(copyBuffer, 0, blockSize);
        }

        return pdbFilePath;
    }
}