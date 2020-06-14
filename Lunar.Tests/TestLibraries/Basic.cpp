#include <Windows.h>

int __stdcall DllMain(void* moduleHandle, unsigned long reason, void* reserved)
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
        case DLL_PROCESS_DETACH:
        {
            break;
        }
    }

    return 1;
}

