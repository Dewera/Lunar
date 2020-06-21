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

        internal TlsDirectory(PEHeaders headers, Memory<byte> imageBlock) : base(headers, imageBlock)
        {
            TlsCallBacks = ReadTlsCallbacks();
        }

        private IEnumerable<TlsCallBack> ReadTlsCallbacks()
        {
            if (!Headers.TryGetDirectoryOffset(Headers.PEHeader.ThreadLocalStorageTableDirectory, out var tlsDirectoryOffset))
            {
                yield break;
            }

            if (Headers.PEHeader.Magic == PEMagic.PE32)
            {
                // Read the TLS directory

                var tlsDirectory = MemoryMarshal.Read<ImageTlsDirectory32>(ImageBlock.Span.Slice(tlsDirectoryOffset));

                if (tlsDirectory.AddressOfCallBacks == 0)
                {
                    yield break;
                }

                var currentCallbackVaOffset = RvaToOffset(VaToRva(tlsDirectory.AddressOfCallBacks));

                while (true)
                {
                    // Read the virtual address of the TLS callback

                    var callbackVa = MemoryMarshal.Read<int>(ImageBlock.Span.Slice(currentCallbackVaOffset));

                    if (callbackVa == 0)
                    {
                        break;
                    }

                    var callbackRva = VaToRva(callbackVa);

                    yield return new TlsCallBack(callbackRva);

                    currentCallbackVaOffset += sizeof(int);
                }
            }

            else
            {
                // Read the TLS directory

                var tlsDirectory = MemoryMarshal.Read<ImageTlsDirectory64>(ImageBlock.Span.Slice(tlsDirectoryOffset));

                if (tlsDirectory.AddressOfCallBacks == 0)
                {
                    yield break;
                }

                var currentCallbackVaOffset = RvaToOffset(VaToRva(tlsDirectory.AddressOfCallBacks));

                while (true)
                {
                    // Read the virtual address of the TLS callback

                    var callbackVa = MemoryMarshal.Read<long>(ImageBlock.Span.Slice(currentCallbackVaOffset));

                    if (callbackVa == 0)
                    {
                        break;
                    }

                    var callbackRva = VaToRva(callbackVa);

                    yield return new TlsCallBack(callbackRva);

                    currentCallbackVaOffset += sizeof(long);
                }
            }
        }
    }
}