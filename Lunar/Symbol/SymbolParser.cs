using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Lunar.Native;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Lunar.Native.Structures;
using Lunar.PortableExecutable;
using Lunar.RemoteProcess.Structures;

namespace Lunar.Symbol
{
    internal sealed class SymbolParser
    {
        internal IntPtr RtlInsertInvertedFunctionTable { get; private set; }

        internal IntPtr RtlRemoveInvertedFunctionTable { get; private set; }

        internal SymbolParser(Module module)
        {
            // Initialise a global mutex to ensure only a single PDB is downloaded concurrently

            if (Mutex.TryOpenExisting("LunarMutex", out var mutex))
            {
                mutex.WaitOne();
            }

            else
            {
                mutex = new Mutex(true, "LunarMutex");
            }

            string pdbFilePath;

            using (mutex)
            {
                pdbFilePath = DownloadPdb(module.PeImage.Value).Result;

                mutex.ReleaseMutex();
            }

            InitialiseSymbols(pdbFilePath, module.BaseAddress);
        }

        private static async Task<string> DownloadPdb(PeImage peImage)
        {
            // Ensure a temporary directory exists on disk to store the PDB

            var directoryInfo = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Lunar", "PDB", peImage.Headers.PEHeader.Magic == PEMagic.PE32 ? "WOW64" : "X64"));

            // Clear the directory if the correct PDB hasn't been downloaded

            var pdbFilePath = Path.Combine(directoryInfo.FullName, $"{peImage.DebugDirectoryData.Path.Replace(".pdb", "")}-{peImage.DebugDirectoryData.Guid.ToString().Replace("-", "")}.pdb");

            foreach (var file in directoryInfo.EnumerateFiles())
            {
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
                    // The file is currently open and cannot be safely deleted
                }
            }

            // Download the PDB from the Microsoft symbol server

            static void ReportDownloadProgress(object sender, ProgressChangedEventArgs eventArgs)
            {
                var progress = eventArgs.ProgressPercentage / 2;

                Console.Write($"\rDownloading required files - [{new string('=', progress)}{new string(' ', 50 - progress)}] - {eventArgs.ProgressPercentage}%");
            }

            var pdbUri = new Uri($"https://msdl.microsoft.com/download/symbols/{peImage.DebugDirectoryData.Path}/{peImage.DebugDirectoryData.Guid.ToString().Replace("-", "")}{peImage.DebugDirectoryData.Age}/{peImage.DebugDirectoryData.Path}");

            using (var webClient = new WebClient())
            {
                webClient.DownloadProgressChanged += ReportDownloadProgress;

                await webClient.DownloadFileTaskAsync(pdbUri, pdbFilePath);
            }

            return pdbFilePath;
        }

        private void InitialiseSymbols(string pdbFilePath, IntPtr dllBaseAddress)
        {
            using var localProcess = Process.GetCurrentProcess();

            // Initialise a symbol handler

            if (!Dbghelp.SymInitialize(localProcess.SafeHandle, null, false))
            {
                throw new Win32Exception($"Failed to call SymInitialize with error code {Marshal.GetLastWin32Error()}");
            }

            Dbghelp.SymSetOptions(SymbolOptions.UndecorateName | SymbolOptions.DeferredLoads | SymbolOptions.AutoPublics);

            // Load the symbol table for the PDB

            var symbolTableAddress = Dbghelp.SymLoadModule64(localProcess.SafeHandle, IntPtr.Zero, pdbFilePath, null, dllBaseAddress.ToInt64(), (int) new FileInfo(pdbFilePath).Length);

            if (symbolTableAddress == 0)
            {
                throw new Win32Exception($"Failed to call SymLoadModule64 with error code {Marshal.GetLastWin32Error()}");
            }

            // Initialise a buffer to receive the symbol information

            var symbolInfoBuffer = new byte[(Unsafe.SizeOf<SymbolInfo>() + Constants.MaxSymbolName * sizeof(char) + sizeof(long) - 1) / sizeof(long) * sizeof(long)];

            MemoryMarshal.Write(symbolInfoBuffer, ref Unsafe.AsRef(new SymbolInfo {SizeOfStruct = Unsafe.SizeOf<SymbolInfo>(), MaxNameLen = Constants.MaxSymbolName}));

            // Retrieve the addresses of the symbols

            IntPtr GetSymbolAddress(string symbolName)
            {
                if (!Dbghelp.SymFromName(localProcess.SafeHandle, symbolName, ref Unsafe.AsRef(Unsafe.As<byte, SymbolInfo>(ref symbolInfoBuffer[0]))))
                {
                    throw new Win32Exception($"Failed to call SymFromName with error code {Marshal.GetLastWin32Error()}");
                }

                return new IntPtr(MemoryMarshal.Read<SymbolInfo>(symbolInfoBuffer).Address);
            }

            RtlInsertInvertedFunctionTable = GetSymbolAddress("RtlInsertInvertedFunctionTable");

            RtlRemoveInvertedFunctionTable = GetSymbolAddress("RtlRemoveInvertedFunctionTable");

            // Clean up the unmanaged resources used by the symbol handler

            if (!Dbghelp.SymCleanup(localProcess.SafeHandle))
            {
                throw new Win32Exception($"Failed to call SymCleanup with error code {Marshal.GetLastWin32Error()}");
            }
        }
    }
}