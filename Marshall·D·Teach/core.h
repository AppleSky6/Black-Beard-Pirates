#pragma once
#include "stdafx.h"
#include "_global.h"
#include <shlobj_core.h>

BOOL GetMemInfo(SIZE_T Address, MEMORY_BASIC_INFORMATION& mic);
LONG WINAPI MyUnhandledExceptionFilter(PEXCEPTION_POINTERS   pExInfo);


