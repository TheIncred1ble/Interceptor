#include "Definitions.h"
#ifdef FEATURE_STACKTRACE_CHECK

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#ifdef FEATURE_DLL_FILTER
#include "DllFilter.h"
#ifdef FEATURE_WINDOWS_HOOKS_FILTER
#include "WinHookFilter.h"
#endif
#endif

#include "StackTraceCheck.h"

namespace StacktraceChecker {
    STACKTRACE_CHECK_RESULT CheckStackTrace(OPTIONAL OUT PVOID* UnknownFrame)
    {
        if (UnknownFrame) *UnknownFrame = NULL;

        PVOID Trace[8];
        WORD Captured = CaptureStackBackTrace(1, sizeof(Trace) / sizeof(*Trace), Trace, NULL);
        if (!Captured) return stError;

        for (WORD i = 0; i < Captured; ++i) {
#ifdef FEATURE_DLL_FILTER
            if (!DllFilter::IsAddressInKnownModule(Trace[i])) {
                if (UnknownFrame) *UnknownFrame = Trace[i];
                return stUnknownModule;
            }
#ifdef FEATURE_WINDOWS_HOOKS_FILTER
            if (WinHooksFilter::IsWinHookOrigin(Trace[i])) {
                if (UnknownFrame) *UnknownFrame = Trace[i];
                return stWindowsHooks;
            }
#endif
#endif
        }

        return stValid;
    }
}

#endif