using System;
using Lunar.Utilities;

namespace Lunar.Remote
{
    internal sealed class SafePebLock : IDisposable
    {
        private readonly ProcessContext _processContext;

        internal SafePebLock(ProcessContext processContext)
        {
            _processContext = processContext;
            processContext.CallRoutine(processContext.GetFunctionAddress("ntdll.dll", "RtlAcquirePebLock"));
        }

        public void Dispose()
        {
            Executor.IgnoreExceptions(() => _processContext.CallRoutine(_processContext.GetFunctionAddress("ntdll.dll", "RtlReleasePebLock")));
        }
    }
}