using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Lunar.Native.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class TlsDirectory : DataDirectory
    {
        internal ImmutableArray<int> TlsCallbackOffsets { get; }

        internal TlsDirectory(ReadOnlyMemory<byte> peBytes, PEHeaders peHeaders) : base(peBytes, peHeaders)
        {
            TlsCallbackOffsets = ReadTlsCallbackOffsets().ToImmutableArray();
        }

        private IEnumerable<int> ReadTlsCallbackOffsets()
        {
            // Calculate offset of the TLS table

            if (!PeHeaders.TryGetDirectoryOffset(PeHeaders.PEHeader.ThreadLocalStorageTableDirectory, out var tlsTableOffset))
            {
                yield break;
            }

            if (PeHeaders.PEHeader.Magic == PEMagic.PE32)
            {
                // Calculate the offset of the TLS callbacks

                var tlsTable = MemoryMarshal.Read<ImageTlsDirectory32>(PeBytes.Slice(tlsTableOffset).Span);

                if (tlsTable.AddressOfCallbacks == 0)
                {
                    yield break;
                }
                
                var tlsCallbacksOffset = RvaToOffset(tlsTable.AddressOfCallbacks - (int) PeHeaders.PEHeader.ImageBase);
                
                // Read the offsets of the TLS callbacks

                for (var tlsCallbackIndex = 0;; tlsCallbackIndex ++)
                {
                    var tlsCallbackVaOffset = tlsCallbacksOffset + sizeof(int) * tlsCallbackIndex;

                    var tlsCallbackVa = MemoryMarshal.Read<int>(PeBytes.Slice(tlsCallbackVaOffset).Span);

                    if (tlsCallbackVa == 0)
                    {
                        break;
                    }

                    yield return tlsCallbackVa - (int) PeHeaders.PEHeader.ImageBase;
                }
            }

            else
            {
                // Calculate the offset of the TLS callbacks

                var tlsTable = MemoryMarshal.Read<ImageTlsDirectory64>(PeBytes.Slice(tlsTableOffset).Span);

                if (tlsTable.AddressOfCallbacks == 0)
                {
                    yield break;
                }

                var tlsCallbacksOffset = RvaToOffset((int) (tlsTable.AddressOfCallbacks - (long) PeHeaders.PEHeader.ImageBase));

                // Read the offsets of the TLS callbacks

                for (var tlsCallbackIndex = 0;; tlsCallbackIndex ++)
                {
                    var tlsCallbackVaOffset = tlsCallbacksOffset + sizeof(long) * tlsCallbackIndex;

                    var tlsCallbackVa = MemoryMarshal.Read<long>(PeBytes.Slice(tlsCallbackVaOffset).Span);

                    if (tlsCallbackVa == 0)
                    {
                        break;
                    }

                    yield return (int) (tlsCallbackVa - (long) PeHeaders.PEHeader.ImageBase);
                }
            }
        }
    }
}