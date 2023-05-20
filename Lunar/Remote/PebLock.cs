using System.Runtime.InteropServices;

namespace Lunar.Remote;

internal sealed class PebLock : IDisposable
{
    private readonly ProcessContext _processContext;

    internal PebLock(ProcessContext processContext)
    {
        _processContext = processContext;
        _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlAcquirePebLock"), CallingConvention.StdCall);
    }

    public void Dispose()
    {
        _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlReleasePebLock"), CallingConvention.StdCall);
    }
}