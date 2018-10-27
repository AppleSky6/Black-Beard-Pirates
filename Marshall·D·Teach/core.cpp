#include "stdafx.h"
#include "core.h"


void CoreInit()
{
	ZWQUERYVIRTUALMEMORY FnZwQueryVirtualMemory;
	FnZwQueryVirtualMemory = (ZWQUERYVIRTUALMEMORY)::GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQueryVirtualMemory");
}


BOOL GetMemInfo(int Address, MEMORY_INFORMATION_CLASS& mic)
{
	ZWQUERYVIRTUALMEMORY FnZwQueryVirtualMemory;
	FnZwQueryVirtualMemory = (ZWQUERYVIRTUALMEMORY)::GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQueryVirtualMemory");
	if (FnZwQueryVirtualMemory(GetCurrentProcess(), (PVOID)Address, MemoryBasicInformation, &mic, sizeof(MEMORY_INFORMATION_CLASS), NULL) == 0)
		return TRUE;
	return FALSE;
}

LONG WINAPI MyUnhandledExceptionFilter(PEXCEPTION_POINTERS pExInfo)
{
	MEMORY_INFORMATION_CLASS mic;
	GetMemInfo(pExInfo->ContextRecord->Eip, mic);
	return EXCEPTION_EXECUTE_HANDLER;
}
