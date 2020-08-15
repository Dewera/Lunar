using System;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class LoadConfigDirectory : DataDirectory
    {
        internal SecurityCookie? SecurityCookie { get; }

        internal SehTable? SehTable { get; }

        internal LoadConfigDirectory(PEHeaders headers, Memory<byte> imageBuffer) : base(headers, imageBuffer)
        {
            SecurityCookie = ReadSecurityCookie();

            SehTable = ReadSehTable();
        }

        private SecurityCookie? ReadSecurityCookie()
        {
            if (!Headers.TryGetDirectoryOffset(Headers.PEHeader.LoadConfigTableDirectory, out var loadConfigDirectoryOffset))
            {
                return null;
            }

            if (Headers.PEHeader.Magic == PEMagic.PE32)
            {
                // Read the load config directory

                var loadConfigDirectory = MemoryMarshal.Read<ImageLoadConfigDirectory32>(ImageBuffer.Span.Slice(loadConfigDirectoryOffset));

                if (loadConfigDirectory.SecurityCookie == 0)
                {
                    return null;
                }

                var cookieRva = VaToRva(loadConfigDirectory.SecurityCookie);

                return new SecurityCookie(cookieRva);
            }

            else
            {
                // Read the load config directory

                var loadConfigDirectory = MemoryMarshal.Read<ImageLoadConfigDirectory64>(ImageBuffer.Span.Slice(loadConfigDirectoryOffset));

                if (loadConfigDirectory.SecurityCookie == 0)
                {
                    return null;
                }

                var cookieRva = VaToRva(loadConfigDirectory.SecurityCookie);

                return new SecurityCookie(cookieRva);
            }
        }

        private SehTable? ReadSehTable()
        {
            if (Headers.PEHeader.Magic == PEMagic.PE32Plus || !Headers.TryGetDirectoryOffset(Headers.PEHeader.LoadConfigTableDirectory, out var loadConfigDirectoryOffset))
            {
                return null;
            }

            // Read the load config directory

            var loadConfigDirectory = MemoryMarshal.Read<ImageLoadConfigDirectory32>(ImageBuffer.Span.Slice(loadConfigDirectoryOffset));

            if (loadConfigDirectory.SEHandlerCount == 0 || loadConfigDirectory.SEHandlerTable == 0)
            {
                return new SehTable(-1, -1);
            }

            var tableRva = VaToRva(loadConfigDirectory.SEHandlerTable);

            return new SehTable(loadConfigDirectory.SEHandlerCount, tableRva);
        }
    }
}