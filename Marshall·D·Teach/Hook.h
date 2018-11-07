#pragma once
#include "stdafx.h"
#include "_global.h"
#include <shlobj_core.h>
#include "Memory.h"
#include <vector>

//定义函数开头大小
//32和64不通后期解决64
#define HANDSIZE 5
//有的系统请求内存
#define EXCEPTIONSIZE	0X100

//定义hook信息结构体
typedef struct FUNINFO
{
	char   pHandlerCode[5];					//扣走的代码（暂定大小是5）
	LONG*  WinApi_ptr		= nullptr;      //被hook api的地址
	LONG*  WinApiStart_ptr	= nullptr;      //正真hook 的地址
	LONG*  HookApi_ptr		= nullptr;      //hook函数的地址
	LONG*  GangPlank_ptr	= nullptr;	    //跳板函数的地址
}*pMDTFunInfo, MDTFunInfo;

//定义可执行内存块信息结构体
typedef struct MEMDUMPINFO
{
	PLONG pMemStart = nullptr;              //内存开始位置
	ULONG MemSize   = NULL;					//内存大小
	ULONG Protect   = NULL;					//保护属性
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

BOOL HookInit();
BOOL SetHookFunctionHandlerCode(pMDTFunInfo FunhanderCode_ptr);
VOID SetGangPlank(pMDTFunInfo FunhanderCode_ptr);
LONG WINAPI ExceptionHandle(_EXCEPTION_POINTERS *excp_pointer);



extern pMDTFunInfo					MDTListFunInfo[10];					//被hook函数信息结构体链表
extern std::vector<pmdzMemDumpInfo>	MDTListMemInfo;						//可执行内存信息
extern wchar_t						g_DumpPath[MAX_PATH];				//桌面文件路径
extern PLONG						GangPlank_ptr;						//跳板位置
extern LONG							GangPlankSize;						//跳板大小
extern BOOL							off;								//hook 了VirtualProtect导致在hook的其他函数的时更改保护属性无限循环 增加开关 hook完所有函数后统一开始干活