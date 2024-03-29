#pragma once

namespace InjectionTypes { // ThreatTypes  (THREAT -> INJECTION)
    enum INJECTION_TYPE {
        ttRemoteThread,
        ttThreadInUnknownModule,
        ttThreadInUnknownMemory,
        ttUnknownOriginModload,
        ttWinHooks,
        ttAppInit,
        ttApc,
        ttContextSteal,
        ttModifiedModule,
        ttUnknownMemory,
        ttUnknown
    };

    struct THREAD_INFO {
        void* EntryPoint;
        void* Argument;
    };

    struct UNKNOWN_ORIGIN_MODLOAD_INFO {
        void* UnknownFrame;
        const wchar_t* Path;
    };

    struct WIN_HOOKS_INFO {
        const wchar_t* Path;
    };

    struct APP_INIT_INFO {
        const wchar_t* Path;
    };

    struct APC_INFO {
        void* ApcRoutine;
        void* Argument;
    };

    struct CONTEXT_STEAL_INFO {
        void* UnknownMemory;
    };

    struct MODIFIED_MODULE_INFO {
        void* ModuleBase;
        const wchar_t* Name;
    };

    struct UNKNOWN_MEMORY_INFO {
        void* AllocationBase;
        size_t Size;
    };

    struct INJECTION_INFO {
        union {
            THREAD_INFO* RemoteThreadInfo;
            THREAD_INFO* ThreadInUnknownModuleInfo;
            THREAD_INFO* ThreadInUnknownMemoryInfo;
            UNKNOWN_ORIGIN_MODLOAD_INFO* UnknownOriginModloadInfo;
            WIN_HOOKS_INFO* WinHooksInfo;
            APP_INIT_INFO* AppInitInfo;
            APC_INFO* ApcInfo;
            CONTEXT_STEAL_INFO* ContextStealInfo;
            MODIFIED_MODULE_INFO* ModifiedModuleInfo;
            UNKNOWN_MEMORY_INFO* UnknownMemoryInfo;
            void* InjectionInfo;
        } Info;
        INJECTION_TYPE Type;
    };

    enum INJECTION_DECISION {
        tdAllow,
        tdTerminate,
        tdBlockOrIgnore,
        tdBlockOrTerminate,
    };

    typedef INJECTION_DECISION(__stdcall* _InjectionNotifier)(INJECTION_INFO* Info);
}