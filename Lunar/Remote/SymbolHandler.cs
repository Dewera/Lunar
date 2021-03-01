using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Lunar.Native;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Lunar.Native.Structures;
using Lunar.Remote.Structures;
using Lunar.Utilities;

namespace Lunar.Remote
{
    internal sealed class SymbolHandler
    {
        private readonly string _pdbFilePath;

        internal SymbolHandler(Process process)
        {
            _pdbFilePath = DependencyManager.FindOrDownloadDependenciesAsync(process).GetAwaiter().GetResult();
        }

        internal Symbol GetSymbol(string symbolName)
        {
            // Initialise the native symbol handler

            Dbghelp.SymSetOptions(SymbolOptions.UndecorateName);

            var currentProcessHandle = Kernel32.GetCurrentProcess();

            if (!Dbghelp.SymInitialize(currentProcessHandle, null, false))
            {
                throw new Win32Exception();
            }

            try
            {
                const int pseudoDllAddress = 0x1000;

                // Load the symbol table for the PDB into the symbol handler

                var pdbSize = new FileInfo(_pdbFilePath).Length;

                var symbolTableAddress = Dbghelp.SymLoadModuleEx(currentProcessHandle, IntPtr.Zero, _pdbFilePath, null, pseudoDllAddress, (int) pdbSize, IntPtr.Zero, 0);

                if (symbolTableAddress == 0)
                {
                    throw new Win32Exception();
                }

                try
                {
                    // Initialise a buffer to store the symbol information

                    Span<byte> symbolInformationBytes = stackalloc byte[(Unsafe.SizeOf<SymbolInfo>() + sizeof(char) * Constants.MaxSymbolNameLength + sizeof(long) - 1) / sizeof(long)];

                    MemoryMarshal.Write(symbolInformationBytes, ref Unsafe.AsRef(new SymbolInfo(Unsafe.SizeOf<SymbolInfo>(), 0, Constants.MaxSymbolNameLength)));

                    // Retrieve the symbol information

                    if (!Dbghelp.SymFromName(currentProcessHandle, symbolName, out Unsafe.As<byte, SymbolInfo>(ref symbolInformationBytes[0])))
                    {
                        throw new Win32Exception();
                    }

                    var symbolInformation = MemoryMarshal.Read<SymbolInfo>(symbolInformationBytes);

                    return new Symbol((int) (symbolInformation.Address - pseudoDllAddress));
                }

                finally
                {
                    Dbghelp.SymUnloadModule64(currentProcessHandle, symbolTableAddress);
                }
            }

            finally
            {
                Dbghelp.SymCleanup(currentProcessHandle);
            }
        }
    }
}