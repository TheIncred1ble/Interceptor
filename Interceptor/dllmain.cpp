// INTERCEPTOR
#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>

#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include "tlhelp32.h"
#include "conio.h"
#include <chrono>
#include <thread>

#include "Globals.h"
#include "Definitions.h"
#include "NtAPI.h"
#include "detours.h"

#include "AllowSystemModules.h"
#include "DLLFilter.h"
#include "WinHookFilter.h"
#include "InjectionHandler.h"
#include "Logger.h"

#include <HookLib.h>

#pragma comment(lib, "ntdll.lib")

#pragma comment(lib, "Zydis.lib")
#pragma comment(lib, "HookLib.lib")
#pragma comment (lib, "detours.lib")

static Notifier::INJECTION_DECISION CALLBACK InjectionNotifier(Notifier::INJECTION_INFO* Info)
{
    return Notifier::tdBlockOrIgnore;
}

static VOID InterInitialize()
{
    if (Globals.Flags.IsInterInitialized) return;

    Log(L"Interceptor initialization...");

#ifdef FEATURE_DLL_FILTER
#ifdef FEATURE_WINDOWS_HOOKS_FILTER
    WinHooksFilter::InitializeWinHooksFilter();
#endif

#ifdef FEATURE_ALLOW_SYSTEM_MODULES
    if (Sfc::InitializeSfc())
        Log(L"AllowSystemModules initialized!");
    else
        Log(L"AllowSystemModules initialization error!");
#endif

    if (DllFilter::EnableDllFilter(FALSE))
        Log(L"DLL Filter enabled!");
    else
        Log(L"DLL Filter initialization error!");
#endif


#ifdef FEATURE_DLL_FILTER
    DllFilter::CollectModulesInfo();
#endif

    Notifier::Subscribe(InjectionNotifier);

    Globals.Flags.IsInterInitialized = TRUE;
    Log(L"Interceptor initialized!");
}

static VOID InterStartDefence()
{
    InterInitialize();
}

static VOID InterStopDefence()
{

#ifdef FEATURE_DLL_FILTER
    DllFilter::DisableDllFilter();
#endif

    Log(L"Interceptor stopped.");
}

#ifdef STATIC_LOAD_AUTOSTART
static VOID NTAPI ApcInitialization(
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
) {
    InterStartDefence();
}
#endif

DWORD PIDByName(WCHAR* AProcessName);
void CheckValues();
template<class Func, class ...Args>
void run(int mins, Func CheckValue);


static VOID InterInitStub(HMODULE hModule, BOOLEAN IsStaticLoaded)
{
#ifdef ENABLE_LOGGING
    InitializeLogging();
#endif

    Log(L"Interceptor started, early phase initialization...");

    Globals.hModules.hInter = hModule;
    Globals.Flags.IsInterStaticLoaded = IsStaticLoaded;

    // hModules initialization:
    Globals.hModules.hNtdll = _GetModuleHandle(L"ntdll.dll");
    Globals.hModules.hKernelBase = _GetModuleHandle(L"kernelbase.dll");
    Globals.hModules.hKernel32 = _GetModuleHandle(L"kernel32.dll");

#ifdef STATIC_LOAD_AUTOSTART
    if (IsStaticLoaded) {
        NtQueueApcThread(
            NtCurrentThread(),
            ApcInitialization,
            NULL,
            NULL,
            0
        );
    }
#endif
    run(1, CheckValues);
}

static VOID InterDeinit()
{
    InterStopDefence();
}

BOOL(WINAPI* pWriteProcessMemory)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    PLONG lpNumberOfBytesWritten);

BOOL WINAPI hookWriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    PLONG lpNumberOfBytesWritten)
{
    HANDLE hookProcess = hProcess;
    //HANDLE myProcess = GetCurrentProcess();
    LPVOID hookBaseAddress = lpBaseAddress;
    LPCVOID hookBuffer = lpBuffer;
    SIZE_T hookSize = nSize;
    LPCVOID myBuffer = NULL;
    SIZE_T mySize = 0;
    Log(L"WriteProcessMemory is IN!");
    Log(L"An attempt to inject code into the process was prevented!");
    //return pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    return pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, mySize, lpNumberOfBytesWritten);
}

BOOL(WINAPI* pReadProcessMemory)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    PLONG lpNumberOfBytesRead);

BOOL WINAPI hookReadProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    PLONG lpNumberOfBytesWritten)
{
    HANDLE hookProcess = hProcess;
    LPVOID hookBaseAddress = lpBaseAddress;
    LPCVOID hookBuffer = lpBuffer;
    SIZE_T hookSize = nSize;
    //Log(L"[i] ReadProcessMemory is IN!");
    return pReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}


DWORD PIDByName(WCHAR* AProcessName)
{
    HANDLE pHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 ProcessEntry;
    DWORD pid;
    ProcessEntry.dwSize = sizeof(ProcessEntry);
    bool Loop = Process32First(pHandle, &ProcessEntry);

    while (Loop)
    {
        if (wcsstr(ProcessEntry.szExeFile, AProcessName))
        {
            pid = ProcessEntry.th32ProcessID;
            CloseHandle(pHandle);
            return pid;
        }
        Loop = Process32Next(pHandle, &ProcessEntry);
    }
    return 0;
}

BOOL check = FALSE;
void CheckValues()
{
    std::string IntAdr, BoolAdr, DoubleAdr;
    std::string s;
    std::ifstream file("Addresses.txt");
    int i = 0;
    if (file.is_open())
    {
        while (getline(file, s))
        {
            if (i == 0)
            {
                IntAdr = s;
            }
            else if (i == 1)
            {
                BoolAdr = s;
            }
            else if (i == 2)
            {
                DoubleAdr = s;
            }
            i++;
        }
        file.close();
        IntAdr.erase(0, IntAdr.find(":") + 2);
        BoolAdr.erase(0, BoolAdr.find(":") + 2);
        DoubleAdr.erase(0, DoubleAdr.find(":") + 2);
        long long AInt = stoll(IntAdr, nullptr, 16);
        long long ABool = stoll(BoolAdr, nullptr, 16);
        long long ADouble = stoll(DoubleAdr, nullptr, 16);

        LPVOID addressInt = (LPVOID)AInt;
        LPVOID addressBool = (LPVOID)ABool;
        LPVOID addressDouble = (LPVOID)ADouble;
        int valueInt;
        bool valueBool;
        double valueDouble;
        int fakeInt;
        bool fakeBool;
        double fakeDouble;
        char buf[255];
        std::string name = "AppToProtect";
        strcpy_s(buf, 255, name.c_str());
        wchar_t wstr[255];
        size_t length = strlen(buf) + 1;
        mbstowcs_s(&length, wstr, length, buf, length);
        DWORD processId = PIDByName(wstr);
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        BOOL ALARM = FALSE;
        int Int = 0;
        bool Bool = FALSE;
        double Double = 0;
        if (!check)
        {
            if (ReadProcessMemory(hProcess, addressInt, &valueInt, sizeof(valueInt), NULL))
            {
                // Вывод считанного значения
                //Log(L"Val Of Integer: " + valueInt);
                Int = valueInt;
                check = TRUE;
            }
            if (ReadProcessMemory(hProcess, addressBool, &valueBool, sizeof(valueBool), NULL))
            {
                // Вывод считанного значения
                //Log(L"Value Of Boolean: " + valueBool);
                Bool = valueBool;
                check = TRUE;
            }
            if (ReadProcessMemory(hProcess, addressDouble, &valueDouble, sizeof(valueDouble), NULL))
            {
                // Вывод считанного значения
                //Log(L"Value Of Double: " + wchar_t(valueDouble));
                Double = valueDouble;
                check = TRUE;
            }
        }
        else
        {
            if (ReadProcessMemory(hProcess, addressInt, &fakeInt, sizeof(fakeInt), NULL))
            {
                if (fakeInt != valueInt)
                {
                    //Log(L"Someone changes your Integer!");
                    ALARM = TRUE;
                }
                else
                    ALARM = FALSE;
            }
            if (ReadProcessMemory(hProcess, addressBool, &fakeBool, sizeof(fakeBool), NULL))
            {
                if (fakeBool != valueBool)
                {
                    //Log(L"Someone changes your Boolean!");
                    ALARM = TRUE;
                }
                else
                    ALARM = FALSE;
            }
            if (ReadProcessMemory(hProcess, addressDouble, &fakeDouble, sizeof(fakeDouble), NULL))
            {
                if (fakeDouble != valueDouble)
                {
                    //Log(L"Someone changes your Double!");
                    ALARM = TRUE;
                }
                else
                    ALARM = FALSE;
            }
        }
        if (ALARM)
        {
            Log(L"An attempt to manipulate the memory of the process has been detected!");
            Log(L"Forced termination of the process.");
            Log(L"Interceptor stopped.");
            __fastfail(0);
        }
    }

}

template<class Func, class ...Args>
void run(int mins, Func CheckValue) {
    auto endless = [=]() {
        while (true) {
            CheckValue();
            std::this_thread::sleep_for(std::chrono::minutes(mins));
        }
    };

    std::thread thread(endless);

    thread.detach();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, PCONTEXT lpContext)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        InterInitStub(hModule, lpContext != NULL);
        pWriteProcessMemory = (BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, PLONG))
            DetourFindFunction("Kernel32.dll", "WriteProcessMemory");
        pReadProcessMemory = (BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, PLONG))
            DetourFindFunction("Kernel32.dll", "ReadProcessMemory");


        if (pReadProcessMemory != NULL)
        {
            // Перехват ReadProcessMemory
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)pReadProcessMemory, hookReadProcessMemory);
            if (DetourTransactionCommit() == NO_ERROR)
            {
                Log(L"ReadProcessMemory() detoured successfully");
            }
        }

        if (pWriteProcessMemory != NULL)
        {
            // Перехват WriteProcessMemory
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)pWriteProcessMemory, hookWriteProcessMemory);
            if (DetourTransactionCommit() == NO_ERROR)
            {
                Log(L"WriteProcessMemory() detoured successfully");
            }
        }


        break;
    case DLL_PROCESS_DETACH:
        InterDeinit();
        break;
    }

    return TRUE;
}




