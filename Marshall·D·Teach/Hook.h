#pragma once
#include "stdafx.h"

typedef struct FUNHANDLECODE
{
	BYTE  opcode;
	DWORD constant;
}*pFunHandleCode, FunHandleCode;

typedef struct FUNINFO
{
	char   pHandlerCode[5];
	LONG*  WinApi_ptr      = nullptr;
	LONG*  WinApiStart_ptr = nullptr;
	LONG*  GangPlank_ptr   = nullptr;
}*pMDTFunInfo, MDTFunInfo;

typedef LONG(__stdcall* tZwAllocateVirtualMemory)(
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID     *BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
	);

LONG WINAPI hkZwAllocateVirtualMemory(
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID     *BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
	);


BOOL GetFunctionHandlerCode(pFunHandleCode FunhanderCode_ptr, DWORD WinAPIAddress, PDWORD pEndAPi_ptr);
BOOL SetHookFunctionHandlerCode(DWORD NewFun_ptr, DWORD oldFun_ptr);
VOID GangPlank();
VOID SetGangPlank(pFunHandleCode FunhanderCode_ptr, LONG pEndAPi_ptr);

LONG GangPlankSize = 60;
