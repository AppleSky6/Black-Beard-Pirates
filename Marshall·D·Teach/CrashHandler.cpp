// CrashHandler.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#pragma warning(disable:4091)
#include <DbgHelp.h>
#include "CrashHandler.h"

TCHAR g_dmpFileName[MAX_PATH] = {};
TCHAR g_crashFileName[MAX_PATH] = {};

typedef LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI *PFNSetUnhandledExceptionFilter)(
	_In_opt_ LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
	);

void DisableSetUnhandledExceptionFilter(LPVOID addrRoutine) {
	DWORD dwOldFlag = 0;
	DWORD dwTempFlag = 0;
	unsigned char code[] = { 0x33, 0xC0, 0xC2, 0x04, 0x00 };
	int nCodeLen = sizeof(code) / sizeof(unsigned char);

	if (!addrRoutine)
		return;

	if (VirtualProtect(addrRoutine, nCodeLen, PAGE_EXECUTE_READWRITE, &dwOldFlag)) {
		WriteProcessMemory(GetCurrentProcess(), addrRoutine, code, nCodeLen, NULL);
	}
	VirtualProtect(addrRoutine, nCodeLen, dwOldFlag, &dwTempFlag);

	return;
}


int WINAPI SetCrashHandle()
{
	PFNSetUnhandledExceptionFilter __SetUnhandledExceptionFilter;

	__SetUnhandledExceptionFilter = (PFNSetUnhandledExceptionFilter)GetProcAddress(LoadLibrary(L"kernel32.dll"), "SetUnhandledExceptionFilter");
	if (!__SetUnhandledExceptionFilter)
		return -EFAULT;

	//顶层异常有bug，顶层异常最后处理
	//SetUnhandledExceptionFilter(NULL);
	//使用veh，第一个处理
	AddVectoredExceptionHandler(1, ExceptionHandle);
	//SetUnhandledExceptionFilter(ExceptionHandle);
	//DisableSetUnhandledExceptionFilter(__SetUnhandledExceptionFilter);
	return 0;
}
