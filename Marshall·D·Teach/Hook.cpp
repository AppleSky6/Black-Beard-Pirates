#include "stdafx.h"
#include "Hook.h"

//��ȡhook��λ�úʹ���
BOOL GetFunctionHandlerCode(pFunHandleCode FunhanderCode_ptr, DWORD WinAPIAddress, PDWORD pEndAPi_ptr)
{
	DWORD oldProtect = NULL;
	DWORD newProtect = NULL;
	BOOL  status = FALSE;

	//PAGE_EXECUTE_READWRITE  Windows Server 2003��Windows XP����Windows XP SP2��Windows Server 2003 SP   ��֧��
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

//��������hook
BOOL SetHookFunctionHandlerCode(DWORD NewFun_ptr, DWORD oldFun_ptr)
{
	DWORD oldProtect = NULL;
	DWORD newProtect = NULL;
	BOOL  status = FALSE;
	DWORD FunOffset = NULL;

	FunOffset = NewFun_ptr - oldFun_ptr - 5;
	//PAGE_EXECUTE_READWRITE  Windows Server 2003��Windows XP����Windows XP SP2��Windows Server 2003 SP   ��֧��
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

//���庯��
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

	//��ȡ��nop�ĵط�
	for (; tmp < GangPlankSize; tmp++)
	{
		if(*(long*)(GangPlank_ptr + tmp) == 0x90)
			break;
	}

	FunhanderCode_ptr += tmp;

	//���ߵĴ���
	*(char*)GangPlank_ptr = FunhanderCode_ptr->opcode;
	*(LONG*)(GangPlank_ptr + 1) = FunhanderCode_ptr->constant;

	//�������
	FunOffset = GangPlank_ptr -  WinAPIAddress;

	//jmp��ԭʼ����
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

