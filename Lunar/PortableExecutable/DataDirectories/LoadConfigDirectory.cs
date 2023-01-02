using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Lunar.Native.Structs;
using Lunar.PortableExecutable.Records;

namespace Lunar.PortableExecutable.DataDirectories;

internal sealed class LoadConfigDirectory : DataDirectoryBase
{
    internal LoadConfigDirectory(PEHeaders headers, Memory<byte> imageBytes) : base(headers.PEHeader!.LoadConfigTableDirectory, headers, imageBytes) { }

    internal LoadConfigData? GetLoadConfigData()
    {
        if (!IsValid)
        {
            return null;
        }

        if (Headers.PEHeader!.Magic == PEMagic.PE32)
        {
            // Read the load config directory

            var loadConfigDirectory = MemoryMarshal.Read<ImageLoadConfigDirectory32>(ImageBytes.Span[DirectoryOffset..]);

            // Parse the exception data

            var exceptionData = Headers.PEHeader!.DllCharacteristics.HasFlag(DllCharacteristics.NoSeh) ? new ExceptionData(-1, -1) : new ExceptionData(loadConfigDirectory.SeHandlerCount, VaToRva(loadConfigDirectory.SeHandlerTable));

            // Parse the security cookie

            var securityCookie = loadConfigDirectory.SecurityCookie == 0 ? null : new SecurityCookie(VaToRva(loadConfigDirectory.SecurityCookie));

            return new LoadConfigData(exceptionData, loadConfigDirectory.GuardFlags, securityCookie);
        }

        else
        {
            // Read the load config directory

            var loadConfigDirectory = MemoryMarshal.Read<ImageLoadConfigDirectory64>(ImageBytes.Span[DirectoryOffset..]);

            // Parse the security cookie

            var securityCookie = loadConfigDirectory.SecurityCookie == 0 ? null : new SecurityCookie(VaToRva(loadConfigDirectory.SecurityCookie));

            return new LoadConfigData(null, loadConfigDirectory.GuardFlags, securityCookie);
        }
    }
}