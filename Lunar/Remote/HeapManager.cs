using System.Diagnostics;
using System.Runtime.InteropServices;
using Lunar.Extensions;
using Lunar.Native.Enums;
using Lunar.Native.Structs;
using Lunar.Utilities;

namespace Lunar.Remote;

internal sealed class HeapManager
{
    private readonly IntPtr _heapAddress;
    private readonly ProcessContext _processContext;

    internal HeapManager(ProcessContext processContext, Process process)
    {
        _heapAddress = GetHeapAddress(process);
        _processContext = processContext;
    }

    internal IntPtr AllocateBuffer(int bufferSize)
    {
        var buffer = _processContext.CallRoutine<IntPtr>(_processContext.GetFunctionAddress("kernel32.dll", "HeapAlloc"), _heapAddress, HeapAllocationType.ZeroMemory, bufferSize);

        if (buffer == IntPtr.Zero)
        {
            throw new ApplicationException("Failed to allocate a buffer in the process heap");
        }

        return buffer;
    }

    internal void FreeBuffer(IntPtr bufferAddress)
    {
        if (!_processContext.CallRoutine<bool>(_processContext.GetFunctionAddress("kernel32.dll", "HeapFree"), _heapAddress, 0, bufferAddress))
        {
            throw new ApplicationException("Failed to free a buffer in the process heap");
        }
    }

    private static IntPtr GetHeapAddress(Process process)
    {
        if (process.GetArchitecture() == Architecture.X86)
        {
            // Read the process WOW64 PEB

            var pebAddress = process.QueryInformation<IntPtr>(ProcessInformationType.Wow64Information);
            var peb = process.ReadStruct<Peb32>(pebAddress);

            return UnsafeHelpers.WrapPointer(peb.ProcessHeap);
        }

        else
        {
            // Read the process PEB

            var basicInformation = process.QueryInformation<ProcessBasicInformation64>(ProcessInformationType.BasicInformation);
            var pebAddress = UnsafeHelpers.WrapPointer(basicInformation.PebBaseAddress);
            var peb = process.ReadStruct<Peb64>(pebAddress);

            return UnsafeHelpers.WrapPointer(peb.ProcessHeap);
        }
    }
}