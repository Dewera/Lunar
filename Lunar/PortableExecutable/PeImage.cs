using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Lunar.Native;
using Lunar.Native.Enumerations;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable
{
    internal sealed class PeImage
    {
        internal CodeViewDebugDirectoryData DebugDirectoryData { get; }

        internal List<ExportedFunction> ExportedFunctions { get; }

        internal PEHeaders Headers { get; }

        internal List<ImportDescriptor> ImportDescriptors { get; }

        internal List<Relocation> Relocations { get; }

        internal SecurityCookie SecurityCookie { get; }

        internal List<TlsCallback> TlsCallbacks { get; }

        private readonly ReadOnlyMemory<byte> _peBytes;

        internal PeImage(ReadOnlyMemory<byte> peBytes)
        {
            _peBytes = peBytes;

            using (var peReader = new PEReader(new MemoryStream(peBytes.ToArray())))
            {
                var debugDirectoryData = peReader.ReadDebugDirectory();

                if (debugDirectoryData[0].Type == DebugDirectoryEntryType.CodeView)
                {
                    DebugDirectoryData = peReader.ReadCodeViewDebugDirectoryData(debugDirectoryData[0]);
                }

                Headers = peReader.PEHeaders;
            }

            ValidatePeImage();

            ExportedFunctions = ParseExportedFunctions();

            ImportDescriptors = ParseImportDescriptors();

            Relocations = ParseRelocations();

            SecurityCookie = ParseSecurityCookie();

            TlsCallbacks = ParseTlsCallbacks();
        }

        private List<ExportedFunction> ParseExportedFunctions()
        {
            var exportedFunctions = new List<ExportedFunction>();

            // Read the export table

            if (Headers.PEHeader.ExportTableDirectory.RelativeVirtualAddress == 0)
            {
                return exportedFunctions;
            }

            var exportTable = MemoryMarshal.Read<ImageExportDirectory>(_peBytes.Slice(RvaToOffset(Headers.PEHeader.ExportTableDirectory.RelativeVirtualAddress)).Span);

            // Read the functions from the export table

            for (var functionIndex = 0; functionIndex < exportTable.NumberOfNames; functionIndex ++)
            {
                // Read the offset of the function

                var functionNameOrdinal = MemoryMarshal.Read<short>(_peBytes.Slice(RvaToOffset(exportTable.AddressOfNameOrdinals) + sizeof(short) * functionIndex).Span);

                var functionOffset = MemoryMarshal.Read<int>(_peBytes.Slice(RvaToOffset(exportTable.AddressOfFunctions) + sizeof(int) * functionNameOrdinal).Span);

                // Read the name of the function

                var functionNameOffset = RvaToOffset(MemoryMarshal.Read<int>(_peBytes.Slice(RvaToOffset(exportTable.AddressOfNames) + sizeof(int) * functionIndex).Span));

                var functionName = ReadNullTerminatedString(functionNameOffset);

                exportedFunctions.Add(new ExportedFunction(functionName, functionOffset, exportTable.Base + functionNameOrdinal));
            }

            return exportedFunctions;
        }

        private List<ImportDescriptor> ParseImportDescriptors()
        {
            var importDescriptors = new List<ImportDescriptor>();

            List<ImportedFunction> ReadImportedFunctions(int descriptorThunkOffset, int importAddressTableOffset)
            {
                var importedFunctions = new List<ImportedFunction>();

                for (var functionIndex = 0;; functionIndex ++)
                {
                    // Calculate the offset of the function

                    var functionOffset = Headers.PEHeader.Magic == PEMagic.PE32 ? importAddressTableOffset + sizeof(int) * functionIndex : importAddressTableOffset + sizeof(long) * functionIndex;

                    // Read the thunk data of the function

                    var functionThunkDataOffset = Headers.PEHeader.Magic == PEMagic.PE32 ? descriptorThunkOffset + sizeof(int) * functionIndex : descriptorThunkOffset + sizeof(long) * functionIndex;

                    int functionDataOffset;

                    if (Headers.PEHeader.Magic == PEMagic.PE32)
                    {
                        var functionThunkData = MemoryMarshal.Read<uint>(_peBytes.Slice(functionThunkDataOffset).Span);

                        if (functionThunkData == 0)
                        {
                            break;
                        }

                        // Determine if the function is imported via ordinal

                        if ((functionThunkData & Constants.OrdinalFlag32) != 0)
                        {
                            importedFunctions.Add(new ImportedFunction(string.Empty, functionOffset, (int) (functionThunkData & ushort.MaxValue)));

                            continue;
                        }

                        functionDataOffset = RvaToOffset((int) functionThunkData);
                    }

                    else
                    {
                        var functionThunkData = MemoryMarshal.Read<ulong>(_peBytes.Slice(functionThunkDataOffset).Span);

                        if (functionThunkData == 0)
                        {
                            break;
                        }

                        // Determine if the function is imported via ordinal

                        if ((functionThunkData & Constants.OrdinalFlag64) != 0)
                        {
                            importedFunctions.Add(new ImportedFunction(string.Empty, functionOffset, (int) (functionThunkData & ushort.MaxValue)));

                            continue;
                        }

                        functionDataOffset = RvaToOffset((int) functionThunkData);
                    }

                    // Read the ordinal of the function

                    var functionOrdinal = MemoryMarshal.Read<short>(_peBytes.Slice(functionDataOffset).Span);

                    // Read the name of the function

                    var functionName = ReadNullTerminatedString(functionDataOffset + sizeof(short));

                    importedFunctions.Add(new ImportedFunction(functionName, functionOffset, functionOrdinal));
                }

                return importedFunctions;
            }

            if (Headers.PEHeader.DelayImportTableDirectory.RelativeVirtualAddress != 0)
            {
                // Calculate the offset the delay import table

                var delayImportTableOffset = RvaToOffset(Headers.PEHeader.DelayImportTableDirectory.RelativeVirtualAddress);

                for (var descriptorIndex = 0;; descriptorIndex ++)
                {
                    // Read the import descriptor

                    var descriptor = MemoryMarshal.Read<ImageDelayLoadDescriptor>(_peBytes.Slice(delayImportTableOffset + Unsafe.SizeOf<ImageDelayLoadDescriptor>() * descriptorIndex).Span);

                    if (descriptor.DllNameRva == 0)
                    {
                        break;
                    }

                    // Read the name of the import descriptor

                    var descriptorNameOffset = RvaToOffset(descriptor.DllNameRva);

                    var descriptorName = ReadNullTerminatedString(descriptorNameOffset);

                    // Read the functions imported under the import descriptor

                    var descriptorThunkOffset = RvaToOffset(descriptor.ImportNameTableRva);

                    var importAddressTableOffset = RvaToOffset(descriptor.ImportAddressTableRva);

                    importDescriptors.Add(new ImportDescriptor(ReadImportedFunctions(descriptorThunkOffset, importAddressTableOffset), descriptorName));
                }
            }

            if (Headers.PEHeader.ImportTableDirectory.RelativeVirtualAddress == 0)
            {
                return importDescriptors;
            }

            // Calculate the offset of the import table

            var importTableOffset = RvaToOffset(Headers.PEHeader.ImportTableDirectory.RelativeVirtualAddress);

            for (var descriptorIndex = 0;; descriptorIndex++)
            {
                // Read the import descriptor

                var descriptor = MemoryMarshal.Read<ImageImportDescriptor>(_peBytes.Slice(importTableOffset + Unsafe.SizeOf<ImageImportDescriptor>() * descriptorIndex).Span);

                if (descriptor.Name == 0)
                {
                    break;
                }

                // Read the name of the import descriptor

                var descriptorNameOffset = RvaToOffset(descriptor.Name);

                var descriptorName = ReadNullTerminatedString(descriptorNameOffset);

                // Read the functions imported under the import descriptor

                var descriptorThunkOffset = descriptor.OriginalFirstThunk == 0 ? RvaToOffset(descriptor.FirstThunk) : RvaToOffset(descriptor.OriginalFirstThunk);

                var importAddressTableOffset = RvaToOffset(descriptor.FirstThunk);

                importDescriptors.Add(new ImportDescriptor(ReadImportedFunctions(descriptorThunkOffset, importAddressTableOffset), descriptorName));
            }

            return importDescriptors;
        }

        private List<Relocation> ParseRelocations()
        {
            var relocations = new List<Relocation>();

            // Calculate the offset of the relocation table

            if (Headers.PEHeader.BaseRelocationTableDirectory.RelativeVirtualAddress == 0)
            {
                return relocations;
            }

            var currentRelocationBlockOffset = RvaToOffset(Headers.PEHeader.BaseRelocationTableDirectory.RelativeVirtualAddress);

            while (true)
            {
                // Read the relocation block

                var relocationBlock = MemoryMarshal.Read<ImageBaseRelocation>(_peBytes.Slice(currentRelocationBlockOffset).Span);

                if (relocationBlock.SizeOfBlock == 0)
                {
                    break;
                }

                // Read the relocations from the relocation block

                var relocationBlockSize = (relocationBlock.SizeOfBlock - Unsafe.SizeOf<ImageBaseRelocation>()) / sizeof(short);

                for (var relocationIndex = 0; relocationIndex < relocationBlockSize; relocationIndex ++)
                {
                    var relocation = MemoryMarshal.Read<ushort>(_peBytes.Slice(currentRelocationBlockOffset + Unsafe.SizeOf<ImageBaseRelocation>() + sizeof(short) * relocationIndex).Span);

                    // The relocation offset is located in the upper 4 bits of the relocation

                    var relocationOffset = relocation & 0xFFF;

                    // The relocation type is located in the lower 12 bits of the relocation

                    var relocationType = relocation >> 12;

                    relocations.Add(new Relocation(RvaToOffset(relocationBlock.VirtualAddress) + relocationOffset, (RelocationType) relocationType));
                }

                // Calculate the offset of the next relocation block

                currentRelocationBlockOffset += relocationBlock.SizeOfBlock;
            }

            return relocations;
        }

        private SecurityCookie ParseSecurityCookie()
        {
            if (Headers.PEHeader.LoadConfigTableDirectory.RelativeVirtualAddress == 0)
            {
                return new SecurityCookie(0);
            }

            if (Headers.PEHeader.Magic == PEMagic.PE32)
            {
                // Read the load config table

                var loadConfigTable = MemoryMarshal.Read<ImageLoadConfigDirectory32>(_peBytes.Slice(RvaToOffset(Headers.PEHeader.LoadConfigTableDirectory.RelativeVirtualAddress)).Span);

                return loadConfigTable.SecurityCookie == 0 ? new SecurityCookie(0) : new SecurityCookie((int) (loadConfigTable.SecurityCookie - (long) Headers.PEHeader.ImageBase));
            }

            else
            {
                // Read the load config table

                var loadConfigTable = MemoryMarshal.Read<ImageLoadConfigDirectory64>(_peBytes.Slice(RvaToOffset(Headers.PEHeader.LoadConfigTableDirectory.RelativeVirtualAddress)).Span);

                return loadConfigTable.SecurityCookie == 0 ? new SecurityCookie(0) : new SecurityCookie((int) (loadConfigTable.SecurityCookie - (long) Headers.PEHeader.ImageBase));
            }
        }

        private List<TlsCallback> ParseTlsCallbacks()
        {
            var tlsCallbacks = new List<TlsCallback>();

            // Calculate the offset of the TLS table

            if (Headers.PEHeader.ThreadLocalStorageTableDirectory.RelativeVirtualAddress == 0)
            {
                return tlsCallbacks;
            }

            var tlsTableOffset = RvaToOffset(Headers.PEHeader.ThreadLocalStorageTableDirectory.RelativeVirtualAddress);

            if (Headers.PEHeader.Magic == PEMagic.PE32)
            {
                // Calculate the offset of the TLS callbacks

                var tlsTable = MemoryMarshal.Read<ImageTlsDirectory32>(_peBytes.Slice(tlsTableOffset).Span);

                if (tlsTable.AddressOfCallbacks == 0)
                {
                    return tlsCallbacks;
                }

                var tlsCallbacksOffset = RvaToOffset((int) (tlsTable.AddressOfCallbacks - (long) Headers.PEHeader.ImageBase));

                // Read the offsets of the TLS callbacks

                for (var tlsCallbackIndex = 0;; tlsCallbackIndex ++)
                {
                    var tlsCallbackRva = MemoryMarshal.Read<int>(_peBytes.Slice(tlsCallbacksOffset + sizeof(int) * tlsCallbackIndex).Span);

                    if (tlsCallbackRva == 0)
                    {
                        break;
                    }

                    tlsCallbacks.Add(new TlsCallback((int) (tlsCallbackRva - (long) Headers.PEHeader.ImageBase)));
                }
            }

            else
            {
                // Calculate the offset of the TLS callbacks

                var tlsTable = MemoryMarshal.Read<ImageTlsDirectory64>(_peBytes.Slice(tlsTableOffset).Span);

                if (tlsTable.AddressOfCallbacks == 0)
                {
                    return tlsCallbacks;
                }

                var tlsCallbacksOffset = RvaToOffset((int) (tlsTable.AddressOfCallbacks - (long) Headers.PEHeader.ImageBase));

                // Read the offsets of the TLS callbacks

                for (var tlsCallbackIndex = 0;; tlsCallbackIndex ++)
                {
                    var tlsCallbackRva = MemoryMarshal.Read<long>(_peBytes.Slice(tlsCallbacksOffset + sizeof(long) * tlsCallbackIndex).Span);

                    if (tlsCallbackRva == 0)
                    {
                        break;
                    }

                    tlsCallbacks.Add(new TlsCallback((int) (tlsCallbackRva - (long) Headers.PEHeader.ImageBase)));
                }
            }

            return tlsCallbacks;
        }

        private string ReadNullTerminatedString(int offset)
        {
            var stringLength = 0;

            while (_peBytes.Span[offset + stringLength] != byte.MinValue)
            {
                stringLength += 1;
            }

            return Encoding.UTF8.GetString(_peBytes.Slice(offset, stringLength).Span);
        }

        private int RvaToOffset(int rva)
        {
            var sectionHeader = Headers.SectionHeaders.First(section => section.VirtualAddress <= rva && section.VirtualAddress + section.VirtualSize > rva);

            return rva - sectionHeader.VirtualAddress + sectionHeader.PointerToRawData;
        }

        private void ValidatePeImage()
        {
            if (!Headers.IsDll)
            {
                throw new BadImageFormatException("The provided file was not a valid DLL");
            }

            if (Headers.CorHeader != null)
            {
                throw new BadImageFormatException("The provided file was a managed DLL and cannot be mapped");
            }
        }
    }
}