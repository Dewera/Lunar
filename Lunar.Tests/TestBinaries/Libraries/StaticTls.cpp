#include <Windows.h>

static int test_flag = 0;
static thread_local int test_variable = 0xFFFF;

void __stdcall Thread(unsigned long* reason)
{
    switch (*reason)
    {
        case DLL_PROCESS_ATTACH:
        {
            if (&test_variable != nullptr)
            {
                test_flag = 1;
            }

            break;
        }
        case DLL_PROCESS_DETACH:
        {
            if (&test_variable != nullptr)
            {
                test_flag = 2;
            }

            break;
        }
    }
}

bool __stdcall DllMain(void* moduleHandle, unsigned long reason, void* reserved)
{
    if (&test_variable == nullptr)
    {
        return false;
    }

    // This will deadlock the Windows loader due to lock enforcement but not Lunar

    auto threadHandle = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(Thread), &reason, 0, nullptr);

    if (!threadHandle)
    {
        return false;
    }

    WaitForSingleObject(threadHandle, INFINITE);
    CloseHandle(threadHandle);

    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
        {
            if (test_flag == 1)
            {
                return true;
            }

            break;
        }
        case DLL_PROCESS_DETACH:
        {
            if (test_flag == 2)
            {
                return true;
            }

            break;
        }
    }

    return false;
}