namespace Lunar.Shellcode.Records;

internal sealed record CallDescriptor<T>(IntPtr Address, IList<T> Arguments, IntPtr ReturnAddress);