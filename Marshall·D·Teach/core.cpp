#include "stdafx.h"
#include "core.h"
#include "Hook.h"

void hook()
{
	DWORD fnNew_ptr = NULL;
	DWORD fnEnd_ptr = NULL;
	DWORD temp = NULL;
	FunHandleCode mdtAllocateMemoryOPcode = { 0 };
	fnNew_ptr = (DWORD)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwAllocateVirtualMemory");
	GetFunctionHandlerCode(&mdtAllocateMemoryOPcode, fnNew_ptr, &fnEnd_ptr);
	SetGangPlank(&mdtAllocateMemoryOPcode, fnEnd_ptr);
	SetHookFunctionHandlerCode((DWORD)hkZwAllocateVirtualMemory, fnEnd_ptr);
}