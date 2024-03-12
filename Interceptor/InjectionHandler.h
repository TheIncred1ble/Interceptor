#pragma once

#include "InjectionTypes.h"

namespace Notifier {
    using namespace InjectionTypes;

    void Subscribe(_InjectionNotifier Notifier);
    void Unsubscribe(_InjectionNotifier Notifier);
    void ClearSubscriptions(_InjectionNotifier Notifier);
    INJECTION_DECISION Report(INJECTION_INFO* Info);
    INJECTION_DECISION Report(INJECTION_TYPE Type, void* InjectionInfo);
    INJECTION_DECISION ReportRemoteThread(void* EntryPoint, void* Argument);
    INJECTION_DECISION ReportThreadInUnknownModule(void* EntryPoint, void* Argument);
    INJECTION_DECISION ReportThreadInUnknownMemory(void* EntryPoint, void* Argument);
    INJECTION_DECISION ReportUnknownOriginModload(void* UnknownFrame, const wchar_t* Path);
    INJECTION_DECISION ReportWinHooks(const wchar_t* Path);
    INJECTION_DECISION ReportAppInit(const wchar_t* Path);
    INJECTION_DECISION ReportApc(void* ApcRoutine, void* Argument);
    INJECTION_DECISION ReportContextSteal(void* UnknownMemory);
    INJECTION_DECISION ReportModifiedModule(void* ModuleBase, const wchar_t* Name);
    INJECTION_DECISION ReportUnknownMemory(void* AllocationBase, size_t Size);
}
