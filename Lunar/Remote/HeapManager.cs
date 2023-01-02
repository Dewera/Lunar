using System.Diagnostics;
using System.Runtime.InteropServices;
using Lunar.Extensions;
using Lunar.Native.Enums;
using Lunar.Native.Structs;

namespace Lunar.Remote;

internal sealed class HeapManager
{
    private readonly ISet<nint> _bufferCache;
    private readonly nint _heapAddress;
    private readonly ProcessContext _processContext;

    internal HeapManager(ProcessContext processContext, Process process)
    {
        _bufferCache = new HashSet<nint>();
        _heapAddress = GetHeapAddress(process);
        _processContext = processContext;
    }

    internal nint AllocateBuffer(int bufferSize)
    {
        var buffer = _processContext.CallRoutine<nint>(_processContext.GetFunctionAddress("kernel32.dll", "HeapAlloc"), _heapAddress, HeapAllocationType.ZeroMemory, bufferSize);

        if (buffer == 0)
        {
            throw new ApplicationException("Failed to allocate a buffer in the process heap");
        }

        _bufferCache.Add(buffer);

        return buffer;
    }

    internal void FreeBuffer(nint bufferAddress)
    {
        if (!_processContext.CallRoutine<bool>(_processContext.GetFunctionAddress("kernel32.dll", "HeapFree"), _heapAddress, 0, bufferAddress))
        {
            throw new ApplicationException("Failed to free a buffer in the process heap");
        }

        _bufferCache.Remove(bufferAddress);
    }

    internal void FreeCachedBuffers()
    {
        foreach (var buffer in _bufferCache)
        {
            FreeBuffer(buffer);
        }
    }

    private static nint GetHeapAddress(Process process)
    {
        if (process.GetArchitecture() == Architecture.X86)
        {
            // Read the process WOW64 PEB

            var pebAddress = process.QueryInformation<nint>(ProcessInformationType.Wow64Information);
            var peb = process.ReadStruct<Peb32>(pebAddress);

            return peb.ProcessHeap;
        }

        else
        {
            // Read the process PEB

            var basicInformation = process.QueryInformation<ProcessBasicInformation64>(ProcessInformationType.BasicInformation);
            var peb = process.ReadStruct<Peb64>((nint) basicInformation.PebBaseAddress);

            return (nint) peb.ProcessHeap;
        }
    }
}