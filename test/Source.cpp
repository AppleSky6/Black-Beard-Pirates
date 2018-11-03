/*#include <windows.h>

bool(*pf)();
unsigned char shellcode[] = {
0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3
};

void main()
{
	LoadLibrary("Marshall·D·Teach.dll");
	char* pByte = (char*)VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
	memset(pByte, 0, 1024);
	memcpy_s(pByte, 1000, shellcode, 6);
	_asm{
		call pByte;
	}
	MessageBox(0, "fasdfa", "fsadfasdf", 0);
}
*/


#include <Windows.h>

NTSTATUS hkZwAllocateVirtualMemory(
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID     *BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
)
{
	return 0;
}

typedef struct FUNHANDLECODE
{
	BYTE  opcode;
	DWORD constant;
}*pFunHandleCode,FunHandleCode;

BOOL GetFunctionHandlerCode(pFunHandleCode FunhanderCode_ptr,DWORD WinAPIAddress,PDWORD pEndAPi_ptr)
{
	DWORD oldProtect = NULL;
	DWORD newProtect = NULL;
	BOOL  status = FALSE;

	//PAGE_EXECUTE_READWRITE  Windows Server 2003和Windows XP：在Windows XP SP2和Windows Server 2003 SP   不支持
	if (VirtualProtect((VOID*)WinAPIAddress, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		memcpy_s(&FunhanderCode_ptr, sizeof(FunHandleCode), (VOID*)WinAPIAddress, 5);
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

BOOL SetHookFunctionHandlerCode(DWORD NewFun_ptr, DWORD oldFun_ptr)
{
	DWORD oldProtect = NULL;
	DWORD newProtect = NULL;
	BOOL  status = FALSE;
	
	_asm
	{
		call  0xFFFFFFFa
	}
	unsigned char  code[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	oldFun_ptr - 5
	//PAGE_EXECUTE_READWRITE  Windows Server 2003和Windows XP：在Windows XP SP2和Windows Server 2003 SP   不支持
	if (VirtualProtect((VOID*)WinAPIAddress, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		memcpy_s(pEndAPi_ptr, 5, (VOID*)FunhanderCode_ptr, 5);

		VirtualProtect((VOID*)WinAPIAddress, 5, oldProtect, &newProtect);
		status = TRUE;
		return status;
	}
	return status;
}


void mian()
{
	DWORD fnAllocateMemory_ptr = NULL;
	DWORD fnEndAllocateMemory_ptr = NULL;
	FunHandleCode mdtAllocateMemoryOPcode = { 0 };
	fnAllocateMemory_ptr = (DWORD)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwAllocateVirtualMemory");

	GetFunctionHandlerCode(&mdtAllocateMemoryOPcode, fnAllocateMemory_ptr,&fnEndAllocateMemory_ptr);
	fnEndAllocateMemory_ptr  - 5 - 

}
