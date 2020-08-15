using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class TlsDirectory : DataDirectory
    {
        internal IEnumerable<TlsCallBack> TlsCallBacks { get; }

        internal TlsDirectory(PEHeaders headers, Memory<byte> imageBuffer) : base(headers, imageBuffer)
        {
            TlsCallBacks = ReadTlsCallBacks();
        }

        private IEnumerable<TlsCallBack> ReadTlsCallBacks()
        {
            if (!Headers.TryGetDirectoryOffset(Headers.PEHeader.ThreadLocalStorageTableDirectory, out var tlsDirectoryOffset))
            {
                yield break;
            }

            if (Headers.PEHeader.Magic == PEMagic.PE32)
            {
                // Read the TLS directory

                var tlsDirectory = MemoryMarshal.Read<ImageTlsDirectory32>(ImageBuffer.Span.Slice(tlsDirectoryOffset));

                if (tlsDirectory.AddressOfCallBacks == 0)
                {
                    yield break;
                }

                var currentCallBackVaOffset = RvaToOffset(VaToRva(tlsDirectory.AddressOfCallBacks));

                while (true)
                {
                    // Read the virtual address of the callback

                    var callBackVa = MemoryMarshal.Read<int>(ImageBuffer.Span.Slice(currentCallBackVaOffset));

                    if (callBackVa == 0)
                    {
                        break;
                    }

                    var callBackRva = VaToRva(callBackVa);

                    yield return new TlsCallBack(callBackRva);

                    // Set the offset of the next callback virtual address

                    currentCallBackVaOffset += sizeof(int);
                }
            }

            else
            {
                // Read the TLS directory

                var tlsDirectory = MemoryMarshal.Read<ImageTlsDirectory64>(ImageBuffer.Span.Slice(tlsDirectoryOffset));

                if (tlsDirectory.AddressOfCallBacks == 0)
                {
                    yield break;
                }

                var currentCallBackVaOffset = RvaToOffset(VaToRva(tlsDirectory.AddressOfCallBacks));

                while (true)
                {
                    // Read the virtual address of the callback

                    var callBackVa = MemoryMarshal.Read<long>(ImageBuffer.Span.Slice(currentCallBackVaOffset));

                    if (callBackVa == 0)
                    {
                        break;
                    }

                    var callBackRva = VaToRva(callBackVa);

                    yield return new TlsCallBack(callBackRva);

                    // Set the offset of the next callback virtual address

                    currentCallBackVaOffset += sizeof(long);
                }
            }
        }
    }
}