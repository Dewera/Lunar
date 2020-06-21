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

        internal LoadConfigDirectory(PEHeaders headers, Memory<byte> imageBlock) : base(headers, imageBlock)
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

            int securityCookieRva;

            if (Headers.PEHeader.Magic == PEMagic.PE32)
            {
                // Read the load config directory

                var loadConfigDirectory = MemoryMarshal.Read<ImageLoadConfigDirectory32>(ImageBlock.Span.Slice(loadConfigDirectoryOffset));

                securityCookieRva = loadConfigDirectory.SecurityCookie == 0 ? 0 : VaToRva(loadConfigDirectory.SecurityCookie);
            }

            else
            {
                // Read the load config directory

                var loadConfigDirectory = MemoryMarshal.Read<ImageLoadConfigDirectory64>(ImageBlock.Span.Slice(loadConfigDirectoryOffset));

                securityCookieRva = loadConfigDirectory.SecurityCookie == 0 ? 0 : VaToRva(loadConfigDirectory.SecurityCookie);
            }

            return new SecurityCookie(securityCookieRva);
        }

        private SehTable? ReadSehTable()
        {
            if (Headers.PEHeader.Magic == PEMagic.PE32Plus || !Headers.TryGetDirectoryOffset(Headers.PEHeader.LoadConfigTableDirectory, out var loadConfigDirectoryOffset))
            {
                return null;
            }

            // Read the load config directory

            var loadConfigDirectory = MemoryMarshal.Read<ImageLoadConfigDirectory32>(ImageBlock.Span.Slice(loadConfigDirectoryOffset));

            var handlerCount = loadConfigDirectory.SEHandlerCount == 0 ? -1 : loadConfigDirectory.SEHandlerCount;

            var tableRva = loadConfigDirectory.SEHandlerTable == 0 ? -1 : VaToRva(loadConfigDirectory.SEHandlerTable);

            return new SehTable(handlerCount, tableRva);
        }
    }
}