using System.Runtime.InteropServices;

namespace Lunar.Shellcode.Records;

internal sealed record CallDescriptor<T>(nint Address, IList<T> Arguments, CallingConvention CallingConvention, nint ReturnAddress);