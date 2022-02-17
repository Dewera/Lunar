namespace Lunar.Remote;

internal sealed class PebLock
{
    private readonly ProcessContext _processContext;

    internal PebLock(ProcessContext processContext)
    {
        _processContext = processContext;
    }

    internal void Acquire()
    {
        _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlAcquirePebLock"));
    }

    internal void Release()
    {
        _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlReleasePebLock"));
    }
}