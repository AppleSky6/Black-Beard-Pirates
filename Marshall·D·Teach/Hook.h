#pragma once
#include "stdafx.h"
#include "_global.h"
#include <shlobj_core.h>
#include "Memory.h"

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


BOOL HookInit();
BOOL SetHookFunctionHandlerCode(pMDTFunInfo FunhanderCode_ptr);
VOID SetGangPlank(pMDTFunInfo FunhanderCode_ptr);
LONG WINAPI ExceptionHandle(_EXCEPTION_POINTERS *excp_pointer);

extern pMDTFunInfo	MDTListFunInfo[10];			//��hook������Ϣ�ṹ������
extern LONG*		GangPlank_ptr;				//����λ��
extern LONG			GangPlankSize;				//�����С
extern wchar_t		g_DumpPath[MAX_PATH];		//�����ļ�·��
