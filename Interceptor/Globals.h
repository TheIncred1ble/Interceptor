#pragma once

typedef struct {
    struct {
        HMODULE hInter; //hAvn
        HMODULE hNtdll;
        HMODULE hKernelBase;
        HMODULE hKernel32;
    } hModules;
    struct {
        BOOLEAN IsInterStaticLoaded : 1; // IsAvnStaticLoaded
        BOOLEAN IsInterInitialized : 1; // IsAvnInitialized
        BOOLEAN IsInterStarted : 1; // IsAvnStarted
        BOOLEAN Reserved : 5;
    } Flags;
} GLOBALS, * PGLOBALS;  // AVN_GLOBALS ; PAVN_GLOBALS

extern GLOBALS Globals;    // AvnGlobals