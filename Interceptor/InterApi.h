#pragma once

#include "InjectionTypes.h"

#ifdef __cplusplus
#ifdef INTERCEPTOR_EXPORTS
// We're building this library:
#define INTER_EXPORT extern "C" __declspec(dllexport)
#else
// We're using this library:
#define INTER_EXPORT extern "C" __declspec(dllimport)
#endif
#else
#ifdef INTERCEPTOR_EXPORTS
// We're building this library:
#define INTER_EXPORT __declspec(dllexport)
#else
// We're using this library:
#define INTER_EXPORT __declspec(dllimport)
#endif
#endif

typedef struct {
    bool(__stdcall* IsStaticLoaded)();
    bool(__stdcall* IsEnabled)();
    bool(__stdcall* Start)();
    void(__stdcall* Stop)();
    void(__stdcall* Lock)();
    void(__stdcall* Unlock)();
    void(__stdcall* Subscribe)(InjectionTypes::_InjectionNotifier Notifier);
    void(__stdcall* Unsubscribe)(InjectionTypes::_InjectionNotifier Notifier);
} INTER_API, * PINTER_API;

INTER_EXPORT PINTER_API Stub;