#include <Windows.h>

static int tls_value = 0;

void __stdcall TlsCallback(void* module_handle, const unsigned long reason, void* reserved)
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
        {
            tls_value = 1;

            break;
        }
        case DLL_PROCESS_DETACH:
        {
            tls_value = 2;

            break;
        }
    }
}

#ifdef _M_AMD64
    #pragma comment (linker, "/INCLUDE:_tls_used")
    #pragma comment (linker, "/INCLUDE:callback")
    #pragma const_seg(".CRT$XLA")
    extern "C" const PIMAGE_TLS_CALLBACK callback = TlsCallback;
    #pragma const_seg()
#endif

#ifdef _M_IX86
    #pragma comment (linker, "/INCLUDE:__tls_used")
    #pragma comment (linker, "/INCLUDE:_callback")
    #pragma data_seg(".CRT$XLA")
    extern "C" PIMAGE_TLS_CALLBACK callback = TlsCallback;
    #pragma data_seg()
#endif

bool __stdcall DllMain(void* module_handle, const unsigned long reason, void* reserved)
{
    return reason == DLL_PROCESS_ATTACH && tls_value == 1 || reason == DLL_PROCESS_DETACH && tls_value == 2;
}