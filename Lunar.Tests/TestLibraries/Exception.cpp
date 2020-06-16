#include <stdexcept>
#include <Windows.h>

void ThrowException() 
{
    throw std::exception();
}

bool __stdcall DllMain(void* moduleHandle, unsigned long reason, void* reserved)
{
    switch (reason) 
    {
        case DLL_PROCESS_ATTACH: 
        case DLL_PROCESS_DETACH:
        {
            try 
            {
                ThrowException();
            }

            catch (...) 
            {
                // Ignore
            }

            break;
        }
    }

    return true;
}