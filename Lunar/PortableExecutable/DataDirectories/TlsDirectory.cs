using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Lunar.Native.Structs;
using Lunar.PortableExecutable.Records;

namespace Lunar.PortableExecutable.DataDirectories;

internal sealed class TlsDirectory : DataDirectoryBase
{
    internal TlsDirectory(PEHeaders headers, Memory<byte> imageBytes) : base(headers.PEHeader!.ThreadLocalStorageTableDirectory, headers, imageBytes) { }

    internal IEnumerable<TlsCallback> GetTlsCallbacks()
    {
        if (!IsValid)
        {
            yield break;
        }

        if (Headers.PEHeader!.Magic == PEMagic.PE32)
        {
            // Read the TLS directory

            var tlsDirectory = MemoryMarshal.Read<ImageTlsDirectory32>(ImageBytes.Span[DirectoryOffset..]);

            if (tlsDirectory.AddressOfCallBacks == 0)
            {
                yield break;
            }

            for (var callbackIndex = 0;; callbackIndex += 1)
            {
                // Read the callback address

                var callbackAddressOffset = RvaToOffset(VaToRva(tlsDirectory.AddressOfCallBacks)) + sizeof(int) * callbackIndex;
                var callbackAddress = MemoryMarshal.Read<int>(ImageBytes.Span[callbackAddressOffset..]);

                if (callbackAddress == 0)
                {
                    break;
                }

                yield return new TlsCallback(VaToRva(callbackAddress));
            }
        }
        else
        {
            // Read the TLS directory

            var tlsDirectory = MemoryMarshal.Read<ImageTlsDirectory64>(ImageBytes.Span[DirectoryOffset..]);

            if (tlsDirectory.AddressOfCallBacks == 0)
            {
                yield break;
            }

            for (var callbackIndex = 0;; callbackIndex += 1)
            {
                // Read the callback address

                var callbackAddressOffset = RvaToOffset(VaToRva(tlsDirectory.AddressOfCallBacks)) + sizeof(long) * callbackIndex;
                var callbackAddress = MemoryMarshal.Read<long>(ImageBytes.Span[callbackAddressOffset..]);

                if (callbackAddress == 0)
                {
                    break;
                }

                yield return new TlsCallback(VaToRva(callbackAddress));
            }
        }
    }
}