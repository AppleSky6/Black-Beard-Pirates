#pragma once
#include "stdafx.h"
#include "_global.h"
#include <shlobj_core.h>
#include "Memory.h"
#include <winternl.h>

//���庯����ͷ��С
//32��64��ͨ���ڽ��64
#define HANDSIZE 5
//�е�ϵͳ�����ڴ�
#define EXCEPTIONSIZE	4096
//�������ɴ洢�ڴ�����
#define MAX_MEMINFO	    20

//����hook��Ϣ�ṹ��
typedef struct FUNINFO
{
	char   pHandlerCode[5];					//���ߵĴ��루�ݶ���С��5��
	LONG*  WinApi_ptr		= nullptr;      //��hook api�ĵ�ַ
	LONG*  WinApiStart_ptr	= nullptr;      //����hook �ĵ�ַ
	LONG*  HookApi_ptr		= nullptr;      //hook�����ĵ�ַ
	LONG*  GangPlank_ptr	= nullptr;	    //���庯���ĵ�ַ
}*pMDTFunInfo, MDTFunInfo;

//�����ִ���ڴ����Ϣ�ṹ��
typedef struct MEMDUMPINFO
{
	PLONG pMemStart = nullptr;              //�ڴ濪ʼλ��
	ULONG MemSize   = NULL;					//�ڴ��С
	ULONG Protect   = NULL;					//��������
	BOOL  log       = TRUE;				//��������
}*pmdzMemDumpInfo,mdzMemDumpInfo;


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

typedef LONG(__stdcall* tZwProtectVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection
	);

LONG WINAPI hkZwProtectVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection
	);

typedef LONG(__stdcall* tZwCreateFile)(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PLARGE_INTEGER     AllocationSize,
	IN ULONG              FileAttributes,
	IN ULONG              ShareAccess,
	IN ULONG              CreateDisposition,
	IN ULONG              CreateOptions,
	IN PVOID              EaBuffer,
	IN ULONG              EaLength
	);

typedef LONG(__stdcall* tRtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR          SourceString
	);

typedef LONG(__stdcall* tZwWriteFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
);

typedef LONG(__stdcall* tZwClose)(
	HANDLE Handle
);

BOOL HookInit();
BOOL SetHookFunctionHandlerCode(MDTFunInfo& FunhanderCode_ptr);
VOID SetGangPlank(MDTFunInfo& FunhanderCode_ptr);
LONG WINAPI ExceptionHandle(_EXCEPTION_POINTERS *excp_pointer);



extern MDTFunInfo					MDTListFunInfo[10];					//��hook������Ϣ�ṹ������
extern mdzMemDumpInfo				MDTListMemInfo[MAX_MEMINFO];		//��ִ���ڴ���Ϣ
extern wchar_t						g_DumpPath[MAX_PATH];				//�����ļ�·��
extern PLONG						GangPlank_ptr;						//����λ��
extern LONG							GangPlankSize;						//�����С
extern BOOL							off;								//hook ��VirtualProtect������hook������������ʱ���ı�����������ѭ�� ���ӿ��� hook�����к�����ͳһ��ʼ�ɻ�

extern tZwAllocateVirtualMemory    mdZwAllocateVirtualMemory;
extern tZwProtectVirtualMemory     mdZwProtectVirtualMemory;
extern tZwCreateFile			   mdZwCreateFile;
extern tRtlInitUnicodeString	   mdRtlInitUnicodeString;
extern tZwWriteFile				   mdZwWriteFile;
extern tZwClose					   mdtZwClose;

