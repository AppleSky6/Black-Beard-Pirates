// CrashHandler.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#pragma warning(disable:4091)
#include <DbgHelp.h>
#include "CrashHandler.h"
#include "Memory.h"
#include <shlobj_core.h>

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
	EXCEPTION_POINTERS ExInfoCopy(*excp_pointer);
	MEMORY_BASIC_INFORMATION mic;
	char* codebuf = nullptr;

	wchar_t DeskPath[255];
	wchar_t PiecePath[255];
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE h_PieceFile = NULL;
	DWORD wByteNum = 0;

	//如果获取产生异常的地址内存属性失败就跳
	//EXCEPTION_CONTINUE_SEARCH 执行下一个异常处理，EXCEPTION_EXECUTE_HANDLER 从产生异常的下一条继续执行产生异常的代码
	if (!GetMemInfo(ExInfoCopy.ContextRecord->Eip, mic))
		return EXCEPTION_CONTINUE_SEARCH;
	//此页面是可执行页面
	if (mic.Protect == PAGE_EXECUTE || mic.Protect == PAGE_EXECUTE_READ)
			return EXCEPTION_CONTINUE_SEARCH;

	//获取可执行代码
	//使用ReadProcessMemory为了方式该内存突然被释放
	codebuf = new char[mic.RegionSize + 1];
	ReadProcessMemory(GetCurrentProcess(), mic.BaseAddress, codebuf, mic.RegionSize, NULL);

	//写文件
	SHGetSpecialFolderPath(0, DeskPath, CSIDL_DESKTOPDIRECTORY, 0);
	wsprintfW(PiecePath, L"%s\\%s\\%x.dmp", DeskPath, VIRUSFOLDE,(PDWORD)(ExInfoCopy.ContextRecord->Esp));
	h_PieceFile = CreateFile(PiecePath, GENERIC_WRITE, NULL, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_PieceFile == INVALID_HANDLE_VALUE)
	{
		//DbgMsg(L"CreateFile faile");
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if (!WriteFile(h_PieceFile, codebuf, mic.RegionSize, &wByteNum, NULL))
	{
		//DbgMsg(L"WriteFile faile");
		CloseHandle(h_PieceFile);
		return EXCEPTION_CONTINUE_SEARCH;
	}

	//DbgMsg(L"WriteFile success");
	CloseHandle(h_PieceFile);
	//更改为可执行

	if (VirtualProtect(mic.BaseAddress, mic.RegionSize,PAGE_EXECUTE_READWRITE, &wByteNum) == 0)
	{
		//DbgMsg(L"VirtualProtect faile");
		//DbgMsg((SIZE_T)mic.BaseAddress);
		return EXCEPTION_CONTINUE_SEARCH;
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}

int WINAPI SetCrashHandle()
{
	PFNSetUnhandledExceptionFilter __SetUnhandledExceptionFilter;

	__SetUnhandledExceptionFilter = (PFNSetUnhandledExceptionFilter)GetProcAddress(LoadLibrary(L"kernel32.dll"), "SetUnhandledExceptionFilter");
	if (!__SetUnhandledExceptionFilter)
		return -EFAULT;

	//SetUnhandledExceptionFilter(NULL);
	SetUnhandledExceptionFilter(ExceptionHandle);
	DisableSetUnhandledExceptionFilter(__SetUnhandledExceptionFilter);

	return 0;
}
