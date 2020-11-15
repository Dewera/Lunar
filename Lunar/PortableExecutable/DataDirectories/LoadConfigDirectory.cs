using System;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Lunar.Native.Structures;
using Lunar.PortableExecutable.Structures;

namespace Lunar.PortableExecutable.DataDirectories
{
    internal sealed class LoadConfigDirectory : DataDirectory
    {
        internal LoadConfigDirectory(PEHeaders headers, Memory<byte> imageBytes) : base(headers, imageBytes, headers.PEHeader!.LoadConfigTableDirectory) { }

        internal ExceptionTable? GetExceptionTable()
        {
            if (!IsValid)
            {
                return null;
            }

            if (Headers.PEHeader!.DllCharacteristics.HasFlag(DllCharacteristics.NoSeh))
            {
                return new ExceptionTable(-1, -1);
            }

            // Read the load config directory

            var loadConfigDirectory = MemoryMarshal.Read<ImageLoadConfigDirectory32>(ImageBytes.Span.Slice(DirectoryOffset));

            var exceptionTableAddress = VaToRva(loadConfigDirectory.SEHandlerTable);

            return new ExceptionTable(loadConfigDirectory.SEHandlerCount, exceptionTableAddress);
        }

        internal SecurityCookie? GetSecurityCookie()
        {
            if (!IsValid)
            {
                return null;
            }

            if (Headers.PEHeader!.Magic == PEMagic.PE32)
            {
                // Read the load config directory

                var loadConfigDirectory = MemoryMarshal.Read<ImageLoadConfigDirectory32>(ImageBytes.Span.Slice(DirectoryOffset));

                if (loadConfigDirectory.SecurityCookie == 0)
                {
                    return null;
                }

                var securityCookieAddress = VaToRva(loadConfigDirectory.SecurityCookie);

                return new SecurityCookie(securityCookieAddress);
            }

            else
            {
                // Read the load config directory

                var loadConfigDirectory = MemoryMarshal.Read<ImageLoadConfigDirectory64>(ImageBytes.Span.Slice(DirectoryOffset));

                if (loadConfigDirectory.SecurityCookie == 0)
                {
                    return null;
                }

                var securityCookieAddress = VaToRva(loadConfigDirectory.SecurityCookie);

                return new SecurityCookie(securityCookieAddress);
            }
        }
    }
}