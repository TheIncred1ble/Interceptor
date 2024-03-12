#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include "InterApi.h"

static INTER_API InterApi = {};

INTER_EXPORT PINTER_API Stub = &InterApi;