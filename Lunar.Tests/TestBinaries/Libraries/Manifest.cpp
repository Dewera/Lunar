#include <string>
#include <Windows.h>
#include <Commctrl.h>
#include <Psapi.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "\"/manifestdependency:type='Win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

bool __stdcall DllMain(void* moduleHandle, unsigned long reason, void* reserved)
{
    InitCommonControls();

    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
        {
            auto moduleHandles = new HMODULE[512];

            EnumProcessModules(GetCurrentProcess(), moduleHandles, sizeof(HMODULE) * 512, nullptr);

            for (auto moduleIndex = 0; moduleIndex < 512; moduleIndex += 1)
            {
                if (moduleHandles[moduleIndex] == nullptr)
                {
                    break;
                }

                auto moduleFilePath = new wchar_t[MAX_PATH];

                GetModuleFileName(moduleHandles[moduleIndex], moduleFilePath, MAX_PATH / sizeof(wchar_t));

                if (std::wstring(moduleFilePath).find(L"WinSxS") != std::wstring::npos)
                {
                    return true;
                }
            }

            return false;
        }
    }

    return true;
}