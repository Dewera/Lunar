#include <stdexcept>
#include <Windows.h>

static int TlsValue = 0;

void __stdcall TlsCallBack(void* moduleHandle, unsigned long reason, void* reserved)
{
    switch (reason) 
    {
        case DLL_PROCESS_ATTACH:
        {
            TlsValue = 1;

            break;
        }
        case DLL_PROCESS_DETACH:
        {
            TlsValue = 2;

            break;
        }
    }
}

#ifdef _WIN64
    #pragma comment (linker, "/INCLUDE:_tls_used")
    #pragma comment (linker, "/INCLUDE:tlsCallbackAddress")
    #pragma const_seg(".CRT$XLA")
    extern "C" const PIMAGE_TLS_CALLBACK tlsCallbackAddress = TlsCallBack;
    #pragma const_seg()
#else
    #pragma comment (linker, "/INCLUDE:__tls_used")
    #pragma comment (linker, "/INCLUDE:_tlsCallbackAddress")
    #pragma data_seg(".CRT$XLA")
    extern "C" PIMAGE_TLS_CALLBACK tlsCallbackAddress = TlsCallBack;
    #pragma data_seg()
#endif

bool __stdcall DllMain(void* moduleHandle, unsigned long reason, void* reserved)
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
        {
            if (TlsValue != 1) 
            {
                throw std::exception();
            }

            break;
        }
        case DLL_PROCESS_DETACH:
        {
            if (TlsValue != 2)
            {
                throw std::exception();
            }

            break;
        }
    }

    return true;
}

