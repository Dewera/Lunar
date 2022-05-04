#include <Windows.h>

static thread_local int test_variable = 0xFCFC;

bool __stdcall DllMain(void* module_handle, const unsigned long reason, void* reserved)
{
    return (reason == DLL_PROCESS_ATTACH || reason == DLL_PROCESS_DETACH) && &test_variable != nullptr && test_variable == 0xFCFC;
}