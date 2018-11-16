#include "stdafx.h"
#include "core.h"


void hook()
{
	PLONG WinApiAddress = NULL;
	HookInit();
	WinApiAddress = (PLONG)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwAllocateVirtualMemory");
	MDTListFunInfo[0].HookApi_ptr		= WinApiAddress;
	MDTListFunInfo[0].WinApiStart_ptr	= WinApiAddress;
	MDTListFunInfo[0].HookApi_ptr		= (PLONG)hkZwAllocateVirtualMemory;
	SetHookFunctionHandlerCode(MDTListFunInfo[0]);

	WinApiAddress = (PLONG)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwProtectVirtualMemory");
	MDTListFunInfo[1].HookApi_ptr = WinApiAddress;
	MDTListFunInfo[1].WinApiStart_ptr = WinApiAddress;
	MDTListFunInfo[1].HookApi_ptr = (PLONG)hkZwProtectVirtualMemory;
	SetHookFunctionHandlerCode(MDTListFunInfo[1]);


	off = TRUE;

}