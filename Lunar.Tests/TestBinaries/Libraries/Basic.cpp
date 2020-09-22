#include <Windows.h>

bool __stdcall DllMain(void* moduleHandle, unsigned long reason, void* reserved)
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
        case DLL_PROCESS_DETACH:
        {
            break;
        }
    }

    return true;
}