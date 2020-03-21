using System;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Lunar.Native.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class LoadConfigDirectory : DataDirectory
    {
        internal int SecurityCookieOffset { get; }

        internal LoadConfigDirectory(ReadOnlyMemory<byte> peBytes, PEHeaders peHeaders) : base(peBytes, peHeaders)
        {
            SecurityCookieOffset = ReadSecurityCookieOffset();
        }

        private int ReadSecurityCookieOffset()
        {
            // Calculate the offset of the load config table

            if (!PeHeaders.TryGetDirectoryOffset(PeHeaders.PEHeader.LoadConfigTableDirectory, out var loadConfigTableOffset))
            {
                return 0;
            }

            if (PeHeaders.PEHeader.Magic == PEMagic.PE32)
            {
                // Read the load config table

                var loadConfigTable = MemoryMarshal.Read<ImageLoadConfigDirectory32>(PeBytes.Slice(loadConfigTableOffset).Span);

                // Calculate the offset of the security cookie

                return loadConfigTable.SecurityCookie == 0 ? 0 : loadConfigTable.SecurityCookie - (int) PeHeaders.PEHeader.ImageBase;
            }

            else
            {
                // Read the load config table

                var loadConfigTable = MemoryMarshal.Read<ImageLoadConfigDirectory64>(PeBytes.Slice(loadConfigTableOffset).Span);

                // Calculate the offset of the security cookie

                return loadConfigTable.SecurityCookie == 0 ? 0 : (int) (loadConfigTable.SecurityCookie - (long) PeHeaders.PEHeader.ImageBase);
            }
        }
    }
}