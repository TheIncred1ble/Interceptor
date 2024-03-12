#include "Definitions.h"
#ifdef ENABLE_LOGGING

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <string>
#include "StrAPI.h"

#include <winternl.h>
#include "NtAPI.h"
#include "locale.h"

using namespace StringsAPI;

static HANDLE hLogFile = INVALID_HANDLE_VALUE;

bool InitializeLogging()
{
    DWORD CurrentPid = GetCurrentProcessId();

#ifdef ENABLE_CONSOLE_OUTPUT
    if (!GetStdHandle(STD_OUTPUT_HANDLE)) {
        AllocConsole();
        AttachConsole(CurrentPid);
        FILE* file = NULL;
        freopen_s(&file, "CONOUT$", "w", stdout);
    }
    setlocale(LC_ALL, "");
#endif

    hLogFile = CreateFile(
        (std::to_wstring(CurrentPid) + L"-InterceptorLog.log").c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    return hLogFile != INVALID_HANDLE_VALUE;
}

void Log(const std::wstring& Text)
{

    if (hLogFile == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME Time;
    GetSystemTime(&Time);

    static const WCHAR CaretReturn[] = L"\r\n";
    std::wstring Str =
        L"[" + IntToWide(Time.wDay) + L"." + IntToWide(Time.wMonth) + L"." + IntToWide(Time.wYear) +
        L", " + IntToWide(Time.wHour) + L":" + IntToWide(Time.wMinute) + L":" + IntToWide(Time.wSecond) +
        L"][P:" + IntToWide(__pid()) +
        L"|T:" + IntToWide(__tid()) +
        L"] " + Text + L"\r\n";

    DWORD Written = 0;
    WriteFile(
        hLogFile,
        Str.c_str(),
        static_cast<DWORD>(Str.length()) * sizeof(WCHAR),
        &Written,
        NULL
    );
}
#endif