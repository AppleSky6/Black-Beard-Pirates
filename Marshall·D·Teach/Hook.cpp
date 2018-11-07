#include "stdafx.h"
#include "Hook.h"

pMDTFunInfo		MDTListFunInfo[10]				= { 0 };
std::vector<pmdzMemDumpInfo>	MDTListMemInfo;
wchar_t			g_DumpPath[MAX_PATH]			= { 0 };
PLONG			GangPlank_ptr					= nullptr;
LONG			GangPlankSize					= NULL;
BOOL            off = FALSE;


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
	MessageBox(0, L"-----------------", L"------------", 0);
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
	DWORD wByteNum = 0;
	char* codebuf = nullptr;
	wchar_t PiecePath[MAX_PATH];
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE h_PieceFile = NULL;

	tZwProtectVirtualMemory oZwProtectVirtualMemory = nullptr;
	oZwProtectVirtualMemory = (tZwProtectVirtualMemory)(MDTListFunInfo[1]->GangPlank_ptr);

	for (auto tmp : MDTListMemInfo)
	{
		if ((tmp->MemSize + (LONG)tmp->pMemStart) > excp_pointer->ContextRecord->Eip && (LONG)tmp->pMemStart <= excp_pointer->ContextRecord->Eip)
		{
			//д�ļ�
			wsprintfW(PiecePath, L"%s\\%x.dmp", g_DumpPath, tmp->pMemStart);
			h_PieceFile = CreateFile(PiecePath, GENERIC_WRITE, NULL, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

			//��ȡ��ִ�д���
			//ʹ��ReadProcessMemoryΪ�˷�ʽ���ڴ�ͻȻ���ͷ�
			codebuf = new char[tmp->MemSize + 1];
			ReadProcessMemory(GetCurrentProcess(), tmp->pMemStart, codebuf, tmp->MemSize, NULL);
			WriteFile(h_PieceFile, codebuf, tmp->MemSize, &wByteNum, NULL);
			delete codebuf;
			CloseHandle(h_PieceFile);

			PVOID tmpStart = tmp->pMemStart;
			ULONG tmpSize = tmp->MemSize;

			//����Ϊ��ִ��
			if (oZwProtectVirtualMemory(GetCurrentProcess(), &tmpStart, &tmpSize, tmp->Protect, &wByteNum) == 0)
			{
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			
			return EXCEPTION_CONTINUE_SEARCH;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

//���庯��
VOID SetGangPlank(pMDTFunInfo FunhanderCode_ptr)
{
	LONG FunOffset = 0;

	//��ȡ���庯���Ŀ�ʼ
	FunhanderCode_ptr->GangPlank_ptr = (LONG*)((LONG)GangPlank_ptr);
	GangPlank_ptr = (PLONG)((LONG)GangPlank_ptr + 10);

	//��ԭ���ߵĴ���
	memcpy_s(FunhanderCode_ptr->GangPlank_ptr, HANDSIZE, FunhanderCode_ptr->pHandlerCode, HANDSIZE);

	//�������
	FunOffset = (LONG)FunhanderCode_ptr->WinApiStart_ptr - ((LONG)FunhanderCode_ptr->GangPlank_ptr + 5);

	//jmp��ԭʼ����
	*(char*)((LONG)FunhanderCode_ptr->GangPlank_ptr + HANDSIZE) = 0xE9;
	*(LONG*)((LONG)FunhanderCode_ptr->GangPlank_ptr + HANDSIZE + 1) = FunOffset;
}

//hook ZwAllocateVirtualMemory �ص�����
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
	PLONG tmpStart = nullptr;
	PLONG tmpSize  = nullptr;
	LONG  status = NULL;
	oZwAllocateVirtualMemory = (tZwAllocateVirtualMemory)(MDTListFunInfo[0]->GangPlank_ptr);

	//�������Ѿ��ύ��ҳ��  ������������
	//if (AllocationType == MEM_COMMIT)
	if (off == true && EXCEPTIONSIZE < *(PLONG)RegionSize)
	{
		//����ǿ�ִ��������ô�͸���Ϊ����ִ��
		if (Protect == PAGE_EXECUTE || Protect == PAGE_EXECUTE_READWRITE || Protect == PAGE_EXECUTE_READ || Protect == PAGE_EXECUTE_WRITECOPY)
		{
			pmdzMemDumpInfo tmpInfo = nullptr;
			tmpInfo = new mdzMemDumpInfo;
			//�����ڴ���Ϣ
			tmpInfo->Protect = Protect;
			//���ı�������
			Protect = PAGE_READWRITE;

			//���庯��
			status = oZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
			tmpInfo->MemSize = *(PLONG)RegionSize;
			tmpInfo->pMemStart = (PLONG)*BaseAddress;
			MDTListMemInfo.push_back(tmpInfo);
			return status;
		}
	}

	//���ĺ��������庯��
	status = oZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	return status;
}


//hook NtProtectVirtualMemory
LONG WINAPI hkZwProtectVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection
)
{
	DWORD wByteNum	= 0;
	LONG  status	= NULL;

	tZwProtectVirtualMemory oZwProtectVirtualMemory = nullptr;
	oZwProtectVirtualMemory = (tZwProtectVirtualMemory)(MDTListFunInfo[1]->GangPlank_ptr);

	if (off == TRUE && EXCEPTIONSIZE < *(PLONG)NumberOfBytesToProtect)
	{
		if (NewAccessProtection == PAGE_EXECUTE || NewAccessProtection == PAGE_EXECUTE_READWRITE || NewAccessProtection == PAGE_EXECUTE_READ || NewAccessProtection == PAGE_EXECUTE_WRITECOPY)
		{

			pmdzMemDumpInfo tmpInfo = nullptr;
			tmpInfo = new mdzMemDumpInfo;
			//�����ڴ���Ϣ
			tmpInfo->Protect = NewAccessProtection;
			//���ı�������
			NewAccessProtection = PAGE_READWRITE;
			status = oZwProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

			tmpInfo->pMemStart = (PLONG)*BaseAddress;
			tmpInfo->MemSize = *(PLONG)NumberOfBytesToProtect;
			
			MDTListMemInfo.push_back(tmpInfo);
			return status;
		}
	}
	status = oZwProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	return status;
}