#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include "InjectionHandler.h"

#include "Locks.h"
#include <set>

namespace Notifier {

    class InjectionReporter final {
    private:
        mutable RWLock Lock;
        std::set<_InjectionNotifier> Notifiers;
    public:
        InjectionReporter(const InjectionReporter&) = delete;
        InjectionReporter(InjectionReporter&&) = delete;
        InjectionReporter& operator = (const InjectionReporter&) = delete;
        InjectionReporter& operator = (InjectionReporter&&) = delete;
        ~InjectionReporter() = default;

        InjectionReporter() : Lock(), Notifiers() {}

        void Subscribe(_InjectionNotifier Notifier) {
            Lock.LockExclusive();
            Notifiers.emplace(Notifier);
            Lock.UnlockExclusive();
        }

        void Unsubscribe(_InjectionNotifier Notifier) {
            Lock.LockExclusive();
            Notifiers.erase(Notifier);
            Lock.UnlockExclusive();
        }

        void ClearSubscriptions() {
            Lock.LockExclusive();
            Notifiers.clear();
            Lock.UnlockExclusive();
        }

        INJECTION_DECISION Report(INJECTION_INFO* Info) const {
            INJECTION_DECISION Decision = tdAllow;
            Lock.LockShared();
            for (const auto& Notifier : Notifiers) {
                if ((Decision = Notifier(Info)) == tdTerminate) __fastfail(0);
                if (Decision != tdAllow) break;
            }
            Lock.UnlockShared();
            return Decision;
        }
    };

    static InjectionReporter Reporter;

    void Subscribe(_InjectionNotifier Notifier) {
        Reporter.Subscribe(Notifier);
    }

    void Unsubscribe(_InjectionNotifier Notifier) {
        Reporter.Unsubscribe(Notifier);
    }

    void ClearSubscriptions(_InjectionNotifier Notifier) {
        Reporter.ClearSubscriptions();
    }

    INJECTION_DECISION Report(INJECTION_INFO* Info) {
        return Reporter.Report(Info);
    }

    INJECTION_DECISION Report(INJECTION_TYPE Type, void* InjectionInfo) {
        INJECTION_INFO Info;
        Info.Info.InjectionInfo = InjectionInfo;
        Info.Type = Type;
        return Report(&Info);
    }

    INJECTION_DECISION ReportRemoteThread(void* EntryPoint, void* Argument) {
        THREAD_INFO InjectionInfo;
        InjectionInfo.EntryPoint = EntryPoint;
        InjectionInfo.Argument = Argument;
        return Report(ttRemoteThread, &InjectionInfo);
    }

    INJECTION_DECISION ReportThreadInUnknownModule(void* EntryPoint, void* Argument) {
        THREAD_INFO InjectionInfo;
        InjectionInfo.EntryPoint = EntryPoint;
        InjectionInfo.Argument = Argument;
        return Report(ttThreadInUnknownModule, &InjectionInfo);
    }

    INJECTION_DECISION ReportThreadInUnknownMemory(void* EntryPoint, void* Argument) {
        THREAD_INFO InjectionInfo;
        InjectionInfo.EntryPoint = EntryPoint;
        InjectionInfo.Argument = Argument;
        return Report(ttThreadInUnknownMemory, &InjectionInfo);
    }

    INJECTION_DECISION ReportUnknownOriginModload(void* UnknownFrame, const wchar_t* Path) {
        UNKNOWN_ORIGIN_MODLOAD_INFO InjectionInfo;
        InjectionInfo.UnknownFrame = UnknownFrame;
        InjectionInfo.Path = Path;
        return Report(ttUnknownOriginModload, &InjectionInfo);
    }

    INJECTION_DECISION ReportWinHooks(const wchar_t* Path) {
        WIN_HOOKS_INFO InjectionInfo;
        InjectionInfo.Path = Path;
        return Report(ttWinHooks, &InjectionInfo);
    }

    INJECTION_DECISION ReportAppInit(const wchar_t* Path) {
        APP_INIT_INFO InjectionInfo;
        InjectionInfo.Path = Path;
        return Report(ttAppInit, &InjectionInfo);
    }

    INJECTION_DECISION ReportApc(void* ApcRoutine, void* Argument) {
        APC_INFO InjectionInfo;
        InjectionInfo.ApcRoutine = ApcRoutine;
        InjectionInfo.Argument = Argument;
        return Report(ttApc, &InjectionInfo);
    }

    INJECTION_DECISION ReportContextSteal(void* UnknownMemory) {
        CONTEXT_STEAL_INFO InjectionInfo;
        InjectionInfo.UnknownMemory = UnknownMemory;
        return Report(ttContextSteal, &InjectionInfo);
    }

    INJECTION_DECISION ReportModifiedModule(void* ModuleBase, const wchar_t* Name) {
        MODIFIED_MODULE_INFO InjectionInfo;
        InjectionInfo.ModuleBase = ModuleBase;
        InjectionInfo.Name = Name;
        return Report(ttModifiedModule, &InjectionInfo);
    }

    INJECTION_DECISION ReportUnknownMemory(void* AllocationBase, size_t Size) {
        UNKNOWN_MEMORY_INFO InjectionInfo;
        InjectionInfo.AllocationBase = AllocationBase;
        InjectionInfo.Size = Size;
        return Report(ttUnknownMemory, &InjectionInfo);
    }
}