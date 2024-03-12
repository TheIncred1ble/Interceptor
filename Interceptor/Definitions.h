#pragma once

#define ENABLE_LOGGING /* Enable logging to the ***-AvnLog.log file */
#ifdef ENABLE_LOGGING
#define ENABLE_CONSOLE_OUTPUT /* Duplicate log output to stdout */
#endif

#define STATIC_LOAD_AUTOSTART /* Autostart immediately after loading (only for static loading) */

#define FEATURE_DLL_FILTER /* To detect unknown or modified modules */

#if defined FEATURE_DLL_FILTER
#define FEATURE_STACKTRACE_CHECK /* Check for unknown modules/memory call stack entries */
#ifdef FEATURE_STACKTRACE_CHECK
#define FEATURE_WINDOWS_HOOKS_FILTER /* Cancel of windows hooks based injections */
#ifdef FEATURE_WINDOWS_HOOKS_FILTER
#define FEATURE_ALLOW_SYSTEM_MODULES /* Allow to inject all system modules by windows hooks */
#endif
#endif
#endif