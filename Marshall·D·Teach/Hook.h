#pragma once
#include "stdafx.h"

//���庯����ͷ��С
//32��64��ͨ���ڽ��64
#define HANDSIZE 5

typedef struct FUNINFO
{
	char   pHandlerCode[5];					//���ߵĴ��루�ݶ���С��5��
	LONG*  WinApi_ptr		= nullptr;      //��hook api�ĵ�ַ
	LONG*  WinApiStart_ptr	= nullptr;      //����hook �ĵ�ַ
	LONG*  HookApi_ptr		= nullptr;      //hook�����ĵ�ַ
	LONG*  GangPlank_ptr	= nullptr;	    //���庯���ĵ�ַ
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
