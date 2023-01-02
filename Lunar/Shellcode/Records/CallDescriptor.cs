namespace Lunar.Shellcode.Records;

internal sealed record CallDescriptor<T>(nint Address, IList<T> Arguments, nint ReturnAddress);