using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Lunar.Extensions;
using Lunar.Native.Enumerations;
using Lunar.Native.Structures;
using Lunar.PortableExecutable;
using Lunar.Remote.Structures;
using Lunar.Shared;

namespace Lunar.Remote
{
    internal sealed class Loader
    {
        private readonly IntPtr _address;

        private readonly Process _process;

        internal Loader(Process process)
        {
            _address = GetLoaderAddress(process);

            _process = process;
        }

        internal Module? GetModule(string moduleName)
        {
            if (_process.GetArchitecture() == Architecture.X86)
            {
                // Read the loader data

                var loaderData = _process.ReadStructure<PebLdrData32>(_address);

                var currentEntryAddress = SafeHelpers.CreateSafePointer(loaderData.InLoadOrderModuleList.Flink);

                while (true)
                {
                    // Read the entry

                    var entry = _process.ReadStructure<LdrDataTableEntry32>(currentEntryAddress);

                    // Read the name of the entry

                    var entryNameAddress = SafeHelpers.CreateSafePointer(entry.BaseDllName.Buffer);

                    var entryName = _process.ReadString(entryNameAddress, entry.BaseDllName.Length);

                    if (moduleName.Equals(entryName, StringComparison.OrdinalIgnoreCase))
                    {
                        // Read the file path of the entry

                        var entryFilePathAddress = SafeHelpers.CreateSafePointer(entry.FullDllName.Buffer);

                        var entryFilePath = _process.ReadString(entryFilePathAddress, entry.FullDllName.Length);

                        if (Environment.Is64BitOperatingSystem)
                        {
                            // Redirect the file path to the WOW64 directory

                            entryFilePath = entryFilePath.Replace("System32", "SysWOW64", StringComparison.OrdinalIgnoreCase);
                        }

                        return new Module(SafeHelpers.CreateSafePointer(entry.DllBase), entryName, new PeImage(File.ReadAllBytes(entryFilePath)));
                    }

                    if (currentEntryAddress.ToInt32() == loaderData.InLoadOrderModuleList.Blink)
                    {
                        break;
                    }

                    currentEntryAddress = SafeHelpers.CreateSafePointer(entry.InLoadOrderLinks.Flink);
                }
            }

            else
            {
                // Read the loader data

                var loaderData = _process.ReadStructure<PebLdrData64>(_address);

                var currentEntryAddress = SafeHelpers.CreateSafePointer(loaderData.InLoadOrderModuleList.Flink);

                while (true)
                {
                    // Read the entry

                    var entry = _process.ReadStructure<LdrDataTableEntry64>(currentEntryAddress);

                    // Read the name of the entry

                    var entryNameAddress = SafeHelpers.CreateSafePointer(entry.BaseDllName.Buffer);

                    var entryName = _process.ReadString(entryNameAddress, entry.BaseDllName.Length);

                    if (moduleName.Equals(entryName, StringComparison.OrdinalIgnoreCase))
                    {
                        // Read the file path of the entry

                        var entryFilePathAddress = SafeHelpers.CreateSafePointer(entry.FullDllName.Buffer);

                        var entryFilePath = _process.ReadString(entryFilePathAddress, entry.FullDllName.Length);

                        return new Module(SafeHelpers.CreateSafePointer(entry.DllBase), entryName, new PeImage(File.ReadAllBytes(entryFilePath)));
                    }

                    if (currentEntryAddress.ToInt64() == loaderData.InLoadOrderModuleList.Blink)
                    {
                        break;
                    }

                    currentEntryAddress = SafeHelpers.CreateSafePointer(entry.InLoadOrderLinks.Flink);
                }
            }

            return null;
        }

        private static IntPtr GetLoaderAddress(Process process)
        {
            if (process.GetArchitecture() == Architecture.X86)
            {
                IntPtr pebAddress;

                if (Environment.Is64BitOperatingSystem)
                {
                    // Query the process for the address of its WOW64 PEB

                    pebAddress = process.QueryInformation<IntPtr>(ProcessInformationType.Wow64Information);
                }

                else
                {
                    // Query the process for its basic information

                    var basicInformation = process.QueryInformation<ProcessBasicInformation32>(ProcessInformationType.BasicInformation);

                    pebAddress = SafeHelpers.CreateSafePointer(basicInformation.PebBaseAddress);
                }

                // Read the PEB

                var peb = process.ReadStructure<Peb32>(pebAddress);

                return SafeHelpers.CreateSafePointer(peb.Ldr);
            }

            else
            {
                // Query the process for its basic information

                var basicInformation = process.QueryInformation<ProcessBasicInformation64>(ProcessInformationType.BasicInformation);

                var pebAddress = SafeHelpers.CreateSafePointer(basicInformation.PebBaseAddress);

                // Read the PEB

                var peb = process.ReadStructure<Peb64>(pebAddress);

                return SafeHelpers.CreateSafePointer(peb.Ldr);
            }
        }
    }
}