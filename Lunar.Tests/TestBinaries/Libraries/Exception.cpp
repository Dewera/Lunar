#include <stdexcept>
#include <Windows.h>

bool __stdcall DllMain(void* module_handle, const unsigned long reason, void* reserved)
{
    if (reason == DLL_PROCESS_ATTACH || reason == DLL_PROCESS_DETACH)
    {
        try
        {
            throw std::exception();
        }

        catch (...)
        {
            return true;
        }
    }

    return false;
}