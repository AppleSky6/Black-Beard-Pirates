#pragma once
#include "stdafx.h"
#include <winternl.h>


typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName
}MEMORY_INFORMATION_CLASS;


NTSTATUS ZwQueryVirtualMemory(
	_In_      HANDLE                   ProcessHandle,
	_In_opt_  PVOID                    BaseAddress,
	_In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
	_Out_     PVOID                    MemoryInformation,
	_In_      SIZE_T                   MemoryInformationLength,
	_Out_opt_ PSIZE_T                  ReturnLength
);


typedef
NTSTATUS
(WINAPI *ZWQUERYVIRTUALMEMORY) (
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength OPTIONAL
	);



void CoreInit();
BOOL GetMemInfo(int Address, MEMORY_INFORMATION_CLASS& mic);
LONG WINAPI MyUnhandledExceptionFilter(PEXCEPTION_POINTERS   pExInfo);


