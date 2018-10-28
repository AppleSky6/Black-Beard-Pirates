// CrashHandler.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#pragma warning(disable:4091)
#include <DbgHelp.h>

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

LONG WINAPI ExceptionHandle(_EXCEPTION_POINTERS *excp_pointer)
{
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi = {};
	TCHAR cmd[MAX_PATH * 4] = {};

	_sntprintf_s(cmd, sizeof(cmd) / sizeof(cmd[0]),
		_T("\"%s\" \"%s\" %d %d %d %d"),
		(LPCTSTR)g_crashFileName, (LPCTSTR)g_dmpFileName,
		GetCurrentProcessId(), GetCurrentThreadId(),
		(DWORD)(DWORD*)excp_pointer, MiniDumpWithFullMemory);

	if (CreateProcess(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
		::WaitForSingleObject(pi.hProcess, 60 * 1000);

		::CloseHandle(pi.hThread);
		::CloseHandle(pi.hProcess);

		::ExitProcess(0);
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

int WINAPI SetCrashHandle()
{
	DWORD	dwLen;
	TCHAR	*p;

	PFNSetUnhandledExceptionFilter __SetUnhandledExceptionFilter;

	__SetUnhandledExceptionFilter = (PFNSetUnhandledExceptionFilter)GetProcAddress(LoadLibrary(_T("kernel32.dll")), "SetUnhandledExceptionFilter");
	if (__SetUnhandledExceptionFilter)
		return -EFAULT;

	dwLen = ::GetModuleFileName(NULL, g_crashFileName, sizeof(g_crashFileName) / sizeof(g_crashFileName[0]));
	if (dwLen == 0 || dwLen >= sizeof(g_crashFileName) / sizeof(g_crashFileName[0]))
		return -ENOMEM;

	p = _tcsrchr(g_crashFileName, _T('\\'));
	if (!p)
		return -EFAULT;
	p++;
	_tcscpy_s(g_dmpFileName, sizeof(g_dmpFileName) / sizeof(g_dmpFileName[0]), p);

	*p = _T('\0');
	_tcscat_s(g_crashFileName, sizeof(g_crashFileName) / sizeof(g_crashFileName[0]), _T("CrashDump.exe"));

	__SetUnhandledExceptionFilter(ExceptionHandle);
	DisableSetUnhandledExceptionFilter(__SetUnhandledExceptionFilter);

	return 0;
}