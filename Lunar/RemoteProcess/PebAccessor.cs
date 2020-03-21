using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Lunar.Extensions;
using Lunar.Native.Enumerations;
using Lunar.Native.PInvoke;
using Lunar.Native.Structures;
using Lunar.RemoteProcess.Structures;
using Lunar.Shared;

namespace Lunar.RemoteProcess
{
    internal sealed class PebAccessor
    {
        internal Lazy<ImmutableDictionary<string, string>> ApiSetMappings { get; }

        private readonly PebData _pebData;

        private readonly Process _process;

        internal PebAccessor(Process process)
        {
            _pebData = ReadPebData(process);

            _process = process;
            
            ApiSetMappings = new Lazy<ImmutableDictionary<string, string>>(ReadApiSetMappings);
        }

        internal IEnumerable<Module> ReadModuleEntries()
        {
            if (_process.GetArchitecture() == Architecture.X86)
            {
                var wow64FilePathRegex = new Regex("System32", RegexOptions.IgnoreCase);
                
                // Read the loader data of the WOW64 PEB

                var loaderData = _process.ReadStructure<PebLdrData32>(_pebData.Loader);

                // Read the entries of the InMemoryOrder linked list

                var currentEntryAddress = loaderData.InMemoryOrderModuleList.Flink;

                var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry32>("InMemoryOrderLinks");

                while (true)
                {
                    var entry = _process.ReadStructure<LdrDataTableEntry32>(new IntPtr(currentEntryAddress- inMemoryOrderLinksOffset.ToInt32()));

                    // Read the file path of the entry

                    var entryFilePathBytes = _process.ReadMemory(new IntPtr(entry.FullDllName.Buffer), entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes.Span);

                    if (Environment.Is64BitOperatingSystem)
                    {
                        entryFilePath = wow64FilePathRegex.Replace(entryFilePath, "SysWOW64");
                    }

                    // Read the name of the entry

                    var entryNameBytes = _process.ReadMemory(new IntPtr(entry.BaseDllName.Buffer), entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes.Span);

                    yield return new Module(new IntPtr(entry.DllBase), entryName, entryFilePath);

                    if (currentEntryAddress == loaderData.InMemoryOrderModuleList.Blink)
                    {
                        break;
                    }

                    // Determine the address of the next entry

                    currentEntryAddress = entry.InMemoryOrderLinks.Flink;
                }
            }

            else
            {
                // Read the loader data of the PEB

                var loaderData = _process.ReadStructure<PebLdrData64>(_pebData.Loader);

                // Read the entries of the InMemoryOrder linked list

                var currentEntryAddress = loaderData.InMemoryOrderModuleList.Flink;

                var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry64>("InMemoryOrderLinks");

                while (true)
                {
                    var entry = _process.ReadStructure<LdrDataTableEntry64>(new IntPtr(currentEntryAddress - inMemoryOrderLinksOffset.ToInt32()));

                    // Read the file path of the entry

                    var entryFilePathBytes = _process.ReadMemory(new IntPtr(entry.FullDllName.Buffer), entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes.Span);

                    // Read the name of the entry

                    var entryNameBytes = _process.ReadMemory(new IntPtr(entry.BaseDllName.Buffer), entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes.Span);

                    yield  return new Module(new IntPtr(entry.DllBase), entryName, entryFilePath);

                    if (currentEntryAddress == loaderData.InMemoryOrderModuleList.Blink)
                    {
                        break;
                    }

                    // Determine the address of the next entry

                    currentEntryAddress = entry.InMemoryOrderLinks.Flink;
                }
            }
        }

        private static PebData ReadPebData(Process process)
        {
            if (process.GetArchitecture() == Architecture.X86)
            {
                // Query the remote process for the address of its WOW64 PEB
                
                var wow64PebAddressBytes = new byte[IntPtr.Size];
                
                var ntStatus = Ntdll.NtQueryInformationProcess(process.SafeHandle, ProcessInformationClass.Wow64Information, ref wow64PebAddressBytes[0], wow64PebAddressBytes.Length, out _);

                if (ntStatus != NtStatus.Success)
                {
                    throw ExceptionBuilder.BuildWin32Exception("NtQueryInformationProcess", ntStatus);
                }
                
                var wow64PebAddress = MemoryMarshal.Read<IntPtr>(wow64PebAddressBytes);
                
                // Read the WOW64 PEB data
                
                var wow64Peb = process.ReadStructure<Peb32>(wow64PebAddress);
                
                return new PebData(new IntPtr(wow64Peb.ApiSetMap), new IntPtr(wow64Peb.Ldr));
            }

            else
            {
                // Query the remote process for its BasicInformation

                var processBasicInformationBytes = new byte[Unsafe.SizeOf<ProcessBasicInformation64>()];

                var ntStatus = Ntdll.NtQueryInformationProcess(process.SafeHandle, ProcessInformationClass.BasicInformation, ref processBasicInformationBytes[0], processBasicInformationBytes.Length, out _);

                if (ntStatus != NtStatus.Success)
                {
                    throw ExceptionBuilder.BuildWin32Exception("NtQueryInformationProcess", ntStatus);
                }
                
                var processBasicInformation = MemoryMarshal.Read<ProcessBasicInformation64>(processBasicInformationBytes);
                
                // Read the PEB data
                
                var peb = process.ReadStructure<Peb64>(new IntPtr(processBasicInformation.PebBaseAddress));

                return new PebData(new IntPtr(peb.ApiSetMap), new IntPtr(peb.Ldr));
            }
        }

        private ImmutableDictionary<string, string> ReadApiSetMappings()
        {
            var apiSetMappings = new Dictionary<string, string>();
            
            // Read the API set namespace

            var apiSetNamespace = _process.ReadStructure<ApiSetNamespace>(_pebData.ApiSetMap);
            
            for (var namespaceEntryIndex = 0; namespaceEntryIndex < apiSetNamespace.Count; namespaceEntryIndex ++)
            {
                // Read the namespace entry

                var namespaceEntryAddress = _pebData.ApiSetMap + apiSetNamespace.EntryOffset + Unsafe.SizeOf<ApiSetNamespaceEntry>() * namespaceEntryIndex;

                var namespaceEntry = _process.ReadStructure<ApiSetNamespaceEntry>(namespaceEntryAddress);

                // Read the name of the namespace entry

                var namespaceEntryNameAddress = _pebData.ApiSetMap + namespaceEntry.NameOffset;

                var namespaceEntryNameBytes = _process.ReadMemory(namespaceEntryNameAddress, namespaceEntry.NameLength);

                var namespaceEntryName = $"{Encoding.Unicode.GetString(namespaceEntryNameBytes.Span)}.dll";
                
                // Read the value entry that the namespace entry maps to

                var valueEntryAddress = _pebData.ApiSetMap + namespaceEntry.ValueOffset;

                var valueEntry = _process.ReadStructure<ApiSetValueEntry>(valueEntryAddress);

                if (valueEntry.ValueCount == 0)
                {
                    continue;
                }
                
                // Read the name of the value entry

                var valueEntryNameAddress = _pebData.ApiSetMap + valueEntry.ValueOffset;

                var valueEntryNameBytes = _process.ReadMemory(valueEntryNameAddress, valueEntry.ValueCount);

                var valueEntryName = Encoding.Unicode.GetString(valueEntryNameBytes.Span);
                
                apiSetMappings.Add(namespaceEntryName, valueEntryName);
            }
            
            return apiSetMappings.ToImmutableDictionary();
        }
    }
}