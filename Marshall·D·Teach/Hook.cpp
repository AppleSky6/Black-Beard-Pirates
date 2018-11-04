#include "stdafx.h"
#include "Hook.h"

//获取hook处位置和代码
BOOL GetFunctionHandlerCode(pFunHandleCode FunhanderCode_ptr, DWORD WinAPIAddress, PDWORD pEndAPi_ptr)
{
	DWORD oldProtect = NULL;
	DWORD newProtect = NULL;
	BOOL  status = FALSE;

	//PAGE_EXECUTE_READWRITE  Windows Server 2003和Windows XP：在Windows XP SP2和Windows Server 2003 SP   不支持
	if (VirtualProtect((VOID*)WinAPIAddress, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		FunhanderCode_ptr->opcode = (BYTE)*(char*)WinAPIAddress;
		FunhanderCode_ptr->constant = *(DWORD*)(WinAPIAddress + 1);
		*pEndAPi_ptr = WinAPIAddress;
		if (FunhanderCode_ptr->opcode == 0xE9)
		{
			if (GetFunctionHandlerCode(FunhanderCode_ptr, FunhanderCode_ptr->constant, pEndAPi_ptr))
			{
				VirtualProtect((VOID*)WinAPIAddress, 5, oldProtect, &newProtect);
				status = TRUE;
				return status;
			}
		}
		VirtualProtect((VOID*)WinAPIAddress, 5, oldProtect, &newProtect);
		status = TRUE;
		return status;
	}
	return status;
}

//用来设置hook
BOOL SetHookFunctionHandlerCode(DWORD NewFun_ptr, DWORD oldFun_ptr)
{
	DWORD oldProtect = NULL;
	DWORD newProtect = NULL;
	BOOL  status = FALSE;
	DWORD FunOffset = NULL;

	FunOffset = NewFun_ptr - oldFun_ptr - 5;
	//PAGE_EXECUTE_READWRITE  Windows Server 2003和Windows XP：在Windows XP SP2和Windows Server 2003 SP   不支持
	if (VirtualProtect((VOID*)oldFun_ptr, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		*(char*)oldFun_ptr = 0xe9;
		*(DWORD*)(oldFun_ptr + 1) = FunOffset;
		VirtualProtect((VOID*)oldFun_ptr, 5, oldProtect, &newProtect);
		status = TRUE;
		return status;
	}
	return status;
}

//跳板函数
VOID GangPlank(
)
{
	_asm {
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
		nop;
	};
}

VOID SetGangPlank(pFunHandleCode FunhanderCode_ptr, LONG WinAPIAddress)
{
	LONG GangPlank_ptr = (LONG)GangPlank;
	LONG tmp = 0;
	LONG FunOffset = 0;

	//获取到nop的地方
	for (; tmp < GangPlankSize; tmp++)
	{
		if(*(long*)(GangPlank_ptr + tmp) == 0x90)
			break;
	}

	FunhanderCode_ptr += tmp;

	//扣走的代码
	*(char*)GangPlank_ptr = FunhanderCode_ptr->opcode;
	*(LONG*)(GangPlank_ptr + 1) = FunhanderCode_ptr->constant;

	//计算距离
	FunOffset = GangPlank_ptr -  WinAPIAddress;

	//jmp到原始函数
	*(char*)(GangPlank_ptr + 5) = 0xE9;
	*(LONG*)(GangPlank_ptr + 5 + 1) = FunOffset;
}

LONG WINAPI hkZwAllocateVirtualMemory(
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID     *BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
)
{
	DWORD Temp = NULL;
	Temp = (DWORD)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwAllocateVirtualMemory");
	tZwAllocateVirtualMemory oZwAllocateVirtualMemory;
	oZwAllocateVirtualMemory = (tZwAllocateVirtualMemory)(Temp + 5);

	if (Protect == PAGE_EXECUTE || Protect == PAGE_EXECUTE_READWRITE || Protect == PAGE_EXECUTE_READ || Protect == PAGE_EXECUTE_WRITECOPY)
		Protect = PAGE_READWRITE;
	//Temp = vFunHandleCode[0].constant;
	oZwAllocateVirtualMemory = 0;

	oZwAllocateVirtualMemory(
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		RegionSize,
		AllocationType,
		Protect);
	return 0;
}

