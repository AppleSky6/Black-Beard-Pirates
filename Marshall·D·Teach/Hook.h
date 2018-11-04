#pragma once
#include "stdafx.h"

//定义函数开头大小
//32和64不通后期解决64
#define HANDSIZE 5

typedef struct FUNINFO
{
	char   pHandlerCode[5];					//扣走的代码（暂定大小是5）
	LONG*  WinApi_ptr		= nullptr;      //被hook api的地址
	LONG*  WinApiStart_ptr	= nullptr;      //正真hook 的地址
	LONG*  HookApi_ptr		= nullptr;      //hook函数的地址
	LONG*  GangPlank_ptr	= nullptr;	    //跳板函数的地址
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


BOOL SetHookFunctionHandlerCode(pMDTFunInfo FunhanderCode_ptr);
VOID GangPlank();
VOID SetGangPlank(pMDTFunInfo FunhanderCode_ptr);

extern pMDTFunInfo	MDTListFunInfo[10];
extern LONG			GangPlankSize;
