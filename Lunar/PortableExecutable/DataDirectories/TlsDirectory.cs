using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class TlsDirectory : DataDirectory
    {
        internal IEnumerable<TlsCallBack> TlsCallBacks { get; }

        internal TlsDirectory(Memory<byte> imageBlock, PEHeaders headers) : base(imageBlock, headers)
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

                var tlsDirectory = ReadStructure<ImageTlsDirectory32>(tlsDirectoryOffset);

                if (tlsDirectory.AddressOfCallBacks == 0)
                {
                    yield break;
                }

                var currentCallbackVaOffset = RvaToOffset(VaToRva(tlsDirectory.AddressOfCallBacks));

                while (true)
                {
                    // Read the virtual address of the TLS callback

                    var callbackVa = ReadStructure<int>(currentCallbackVaOffset);

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

                var tlsDirectory = ReadStructure<ImageTlsDirectory64>(tlsDirectoryOffset);

                if (tlsDirectory.AddressOfCallBacks == 0)
                {
                    yield break;
                }

                var currentCallbackVaOffset = RvaToOffset(VaToRva(tlsDirectory.AddressOfCallBacks));

                while (true)
                {
                    // Read the virtual address of the TLS callback

                    var callbackVa = ReadStructure<long>(currentCallbackVaOffset);

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