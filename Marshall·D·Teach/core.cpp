#include "stdafx.h"
#include "core.h"
#include "Hook.h"

void hook()
{
	PLONG WinApiAddress = NULL;
	for (int i = 0; i <= 10; i++)
	{
		pMDTFunInfo mdt = new MDTFunInfo;
		MDTListFunInfo[i] = mdt;
	}
	

	MessageBox(0, L"-------------------", L"GSDFG", 0);
	WinApiAddress = (PLONG)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwAllocateVirtualMemory");
	MDTListFunInfo[0]->HookApi_ptr		= WinApiAddress;
	MDTListFunInfo[0]->WinApiStart_ptr	= WinApiAddress;
	MDTListFunInfo[0]->HookApi_ptr		= (PLONG)hkZwAllocateVirtualMemory;
	SetHookFunctionHandlerCode(MDTListFunInfo[0]);
	MessageBox(0, L"GDFSG", L"GSDFG", 0);
}