using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Lunar.Native;
using Lunar.Native.Enums;
using Lunar.Native.PInvoke;
using Lunar.Native.Structs;
using Lunar.Remote.Records;

namespace Lunar.Remote
{
    internal sealed class SymbolHandler
    {
        private readonly string _pdbFilePath;

        internal SymbolHandler(Architecture architecture)
        {
            _pdbFilePath = FindOrDownloadSymbolFileAsync(architecture).GetAwaiter().GetResult();
        }

        internal Symbol GetSymbol(string symbolName)
        {
            // Initialise a native symbol handler

            if (!Dbghelp.SymSetOptions(SymbolOptions.UndecorateName).HasFlag(SymbolOptions.UndecorateName))
            {
                throw new Win32Exception();
            }

            if (!Dbghelp.SymInitialize(Kernel32.GetCurrentProcess(), null, false))
            {
                throw new Win32Exception();
            }

            try
            {
                const int pseudoDllAddress = 0x1000;

                // Load the symbol file into the symbol handler

                var symbolFileSize = new FileInfo(_pdbFilePath).Length;
                var symbolTableAddress = Dbghelp.SymLoadModuleEx(Kernel32.GetCurrentProcess(), IntPtr.Zero, _pdbFilePath, null, pseudoDllAddress, (int) symbolFileSize, IntPtr.Zero, 0);

                if (symbolTableAddress == 0)
                {
                    throw new Win32Exception();
                }

                try
                {
                    // Initialise a buffer to store the symbol information

                    Span<byte> symbolInformationBytes = stackalloc byte[(Unsafe.SizeOf<SymbolInfo>() + sizeof(char) * Constants.MaxSymbolName + sizeof(long) - 1) / sizeof(long)];
                    MemoryMarshal.Write(symbolInformationBytes, ref Unsafe.AsRef(new SymbolInfo(Unsafe.SizeOf<SymbolInfo>(), 0, Constants.MaxSymbolName)));

                    // Retrieve the symbol information

                    if (!Dbghelp.SymFromName(Kernel32.GetCurrentProcess(), symbolName, out symbolInformationBytes[0]))
                    {
                        throw new Win32Exception();
                    }

                    var symbolInformation = MemoryMarshal.Read<SymbolInfo>(symbolInformationBytes);

                    return new Symbol((int) (symbolInformation.Address - pseudoDllAddress));
                }

                finally
                {
                    Dbghelp.SymUnloadModule64(Kernel32.GetCurrentProcess(), symbolTableAddress);
                }
            }

            finally
            {
                Dbghelp.SymCleanup(Kernel32.GetCurrentProcess());
            }
        }

        private static async Task<string> FindOrDownloadSymbolFileAsync(Architecture architecture)
        {
            // Read the PDB data of ntdll.dll

            var systemDirectoryPath = architecture == Architecture.X86 ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) : Environment.SystemDirectory;
            var ntdllFilePath = Path.Combine(systemDirectoryPath, "ntdll.dll");

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