#include <Windows.h>

static thread_local int test_variable = 0xFCFC;

bool __stdcall DllMain(void* moduleHandle, unsigned long reason, void* reserved)
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
        case DLL_PROCESS_DETACH:
        {
            if (&test_variable != nullptr && test_variable == 0xFCFC)
            {
                return true;
            }
        }
    }

    return false;
}