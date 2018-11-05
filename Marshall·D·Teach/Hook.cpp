#include "stdafx.h"
#include "Hook.h"

pMDTFunInfo	MDTListFunInfo[10]		= { 0 };
wchar_t		g_DumpPath[MAX_PATH]	= { 0 };
PLONG		GangPlank_ptr			= nullptr;
LONG		GangPlankSize			= 60;

//hookǰ��Ϣ�ĳ�ʼ��
BOOL HookInit()
{
	HWND	hwdDeskDir			= NULL;
	wchar_t DeskPath[MAX_PATH]	= { 0 };

	//Ϊhook������Ϣ�ṹ������ָ���ʼ��
	for (int i = 0; i <= 10; i++)
	{
		pMDTFunInfo mdt = new MDTFunInfo;
		MDTListFunInfo[i] = mdt;
	}

	//��ȡ����·���ļ�·��
	SHGetSpecialFolderPath(0, DeskPath, CSIDL_DESKTOPDIRECTORY, 0);
	wsprintfW(g_DumpPath, L"%s\\%s", DeskPath, DUMPFOLDE);

	//��������ڵĻ�����
	//if(ERROR_FILE_EXISTS == SHCreateDirectory(hwdDeskDir, wcWrokPath))
	SHCreateDirectory(hwdDeskDir, g_DumpPath);

	//��������
	GangPlank_ptr = (PLONG)VirtualAlloc(NULL, GangPlankSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (GangPlank_ptr == NULL)
	{
		return FALSE;
	}
	memset(GangPlank_ptr, 0x90, GangPlankSize);
	return TRUE;
}

//��ȡhook��λ�úʹ���
BOOL SetHookFunctionHandlerCode(pMDTFunInfo FunhanderCode_ptr)
{
	DWORD oldProtect = NULL;
	DWORD newProtect = NULL;
	BOOL  status     = FALSE;
	LONG  FunOfset   = NULL;

	//��ȡ���պ�����ַ
	FunOfset = (LONG)FunhanderCode_ptr->HookApi_ptr - (LONG)FunhanderCode_ptr->WinApiStart_ptr - HANDSIZE;

	//PAGE_EXECUTE_READWRITE  Windows Server 2003��Windows XP����Windows XP SP2��Windows Server 2003 SP   ��֧��
	if (VirtualProtect(FunhanderCode_ptr->WinApiStart_ptr, HANDSIZE, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		//��ȡͷ������
		memcpy_s(FunhanderCode_ptr->pHandlerCode, HANDSIZE, FunhanderCode_ptr->WinApiStart_ptr, HANDSIZE);
		//����Ѿ���hook����ô����
		if (FunhanderCode_ptr->pHandlerCode[0] == 0xE9)
		{
			//׼���ڴ���ת
			FunhanderCode_ptr->WinApiStart_ptr = (PLONG)(FunhanderCode_ptr->pHandlerCode);
			if (SetHookFunctionHandlerCode(FunhanderCode_ptr))
			{
				//hook
				FunhanderCode_ptr->WinApiStart_ptr[0] = 0xE9;
				*(PLONG)((LONG)FunhanderCode_ptr->WinApiStart_ptr + 1) = FunOfset;

				SetGangPlank(FunhanderCode_ptr);

				//��ԭҳ����
				VirtualProtect(FunhanderCode_ptr->WinApiStart_ptr, HANDSIZE, oldProtect, &newProtect);
				status = TRUE;
				return status;
			}
			return  status;
		}
		//hook
		FunhanderCode_ptr->WinApiStart_ptr[0] = 0xE9;
		*(PLONG)((LONG)FunhanderCode_ptr->WinApiStart_ptr + 1) = FunOfset;

		SetGangPlank(FunhanderCode_ptr);

		//��ԭҳ����
		VirtualProtect(FunhanderCode_ptr->WinApiStart_ptr, HANDSIZE, oldProtect, &newProtect);
		status = TRUE;
		return status;
	}
	return status;
}

//�쳣����
LONG WINAPI ExceptionHandle(_EXCEPTION_POINTERS *excp_pointer)
{
	EXCEPTION_POINTERS ExInfoCopy(*excp_pointer);
	MEMORY_BASIC_INFORMATION mic;
	char* codebuf = nullptr;
	wchar_t PiecePath[255];
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE h_PieceFile = NULL;
	DWORD wByteNum = 0;

	//�����ȡ�����쳣�ĵ�ַ�ڴ�����ʧ�ܾ���
	//EXCEPTION_CONTINUE_SEARCH ִ����һ���쳣����EXCEPTION_EXECUTE_HANDLER �Ӳ����쳣����һ������ִ�в����쳣�Ĵ���
	if (!GetMemInfo(ExInfoCopy.ContextRecord->Eip, mic))
		return EXCEPTION_CONTINUE_SEARCH;
	//��ҳ���ǿ�ִ��ҳ��
	if (mic.Protect == PAGE_EXECUTE || mic.Protect == PAGE_EXECUTE_READ)
		return EXCEPTION_CONTINUE_SEARCH;

	//��ȡ��ִ�д���
	//ʹ��ReadProcessMemoryΪ�˷�ʽ���ڴ�ͻȻ���ͷ�
	codebuf = new char[mic.RegionSize + 1];
	ReadProcessMemory(GetCurrentProcess(), mic.BaseAddress, codebuf, mic.RegionSize, NULL);

	//д�ļ�
	wsprintfW(PiecePath, L"%s\\%x.dmp", g_DumpPath, DUMPFOLDE, (PDWORD)(ExInfoCopy.ContextRecord->Esp));
	h_PieceFile = CreateFile(PiecePath, GENERIC_WRITE, NULL, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_PieceFile == INVALID_HANDLE_VALUE)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if (!WriteFile(h_PieceFile, codebuf, mic.RegionSize, &wByteNum, NULL))
	{
		CloseHandle(h_PieceFile);
		return EXCEPTION_CONTINUE_SEARCH;
	}

	CloseHandle(h_PieceFile);

	//����Ϊ��ִ��
	if (VirtualProtect(mic.BaseAddress, mic.RegionSize, PAGE_EXECUTE_READWRITE, &wByteNum) == 0)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}

//���庯��
VOID SetGangPlank(pMDTFunInfo FunhanderCode_ptr)
{
	LONG tmp = 0;
	LONG FunOffset = 0;


	//��ȡ��nop�ĵط�
	for (; tmp < GangPlankSize; tmp++)
	{
		if (*(char*)((LONG)GangPlank_ptr + tmp) == 0x90)
			break;
	}

	//��ȡ���庯���Ŀ�ʼ
	FunhanderCode_ptr->GangPlank_ptr = (LONG*)((LONG)GangPlank_ptr + tmp);

	//��ԭ���ߵĴ���
	memcpy_s(FunhanderCode_ptr->GangPlank_ptr, HANDSIZE, FunhanderCode_ptr->pHandlerCode, HANDSIZE);

	//�������
	FunOffset = (LONG)FunhanderCode_ptr->WinApiStart_ptr - ((LONG)FunhanderCode_ptr->GangPlank_ptr + 5);

	//jmp��ԭʼ����
	*(char*)((LONG)FunhanderCode_ptr->GangPlank_ptr + HANDSIZE) = 0xE9;
	*(LONG*)((LONG)FunhanderCode_ptr->GangPlank_ptr + HANDSIZE + 1) = FunOffset;
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
	tZwAllocateVirtualMemory oZwAllocateVirtualMemory = nullptr;
	//����ǿ�ִ��������ô�͸���Ϊ����ִ��
	if (Protect == PAGE_EXECUTE || Protect == PAGE_EXECUTE_READWRITE || Protect == PAGE_EXECUTE_READ || Protect == PAGE_EXECUTE_WRITECOPY)
		Protect = PAGE_READWRITE;
	//���ĺ��������庯��
	oZwAllocateVirtualMemory = (tZwAllocateVirtualMemory)(MDTListFunInfo[0]->GangPlank_ptr);
	oZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	return 0;
}

