#include "stdafx.h"
#include "Hook.h"
#include "../include/peconv.h"

#pragma comment(lib,"../lib/libpeconv.lib")
MDTFunInfo		MDTListFunInfo[10]				= { 0 };
mdzMemDumpInfo  MDTListMemInfo[20]				= { 0 };	
wchar_t			g_DumpPath[MAX_PATH]			= { 0 };
PLONG			GangPlank_ptr					= nullptr;
LONG			GangPlankSize					= 0x1024;
BOOL            off = FALSE;

tZwAllocateVirtualMemory    mdZwAllocateVirtualMemory	= nullptr;
tZwProtectVirtualMemory     mdZwProtectVirtualMemory	= nullptr;
tZwCreateFile				mdZwCreateFile				= nullptr;
tRtlInitUnicodeString		mdRtlInitUnicodeString		= nullptr;
tZwWriteFile				mdZwWriteFile				= nullptr;
tZwClose					mdZwClose					= nullptr;

//hookǰ��Ϣ�ĳ�ʼ��
BOOL HookInit()
{
	HWND	hwdDeskDir			= NULL;
	wchar_t DeskPath[MAX_PATH]	= { 0 };
	CHAR    ntdllPath[MAX_PATH] = { 0 };
	size_t  v_size = 0;

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

	ExpandEnvironmentStringsA("%SystemRoot%\\system32\\ntdll.dll", ntdllPath, MAX_PATH);
	BYTE *ntdll_module = peconv::load_pe_module(ntdllPath, v_size, true, true);
	mdZwAllocateVirtualMemory = (tZwAllocateVirtualMemory)peconv::get_exported_func(ntdll_module, (LPSTR)"ZwAllocateVirtualMemory");
	mdZwProtectVirtualMemory = (tZwProtectVirtualMemory)peconv::get_exported_func(ntdll_module, (LPSTR)"ZwProtectVirtualMemory");
	mdZwCreateFile = (tZwCreateFile)peconv::get_exported_func(ntdll_module, (LPSTR)"ZwCreateFile");
	mdRtlInitUnicodeString = (tRtlInitUnicodeString)peconv::get_exported_func(ntdll_module, (LPSTR)"RtlInitUnicodeString");
	mdZwWriteFile = (tZwWriteFile)peconv::get_exported_func(ntdll_module, (LPSTR)"ZwWriteFile");
	mdZwClose = (tZwClose)peconv::get_exported_func(ntdll_module, (LPSTR)"ZwClose");
	
	
	return TRUE;
}

//��ȡhook��λ�úʹ���
BOOL SetHookFunctionHandlerCode(MDTFunInfo& FunhanderCode_ptr)
{
	DWORD oldProtect = NULL;
	DWORD newProtect = PAGE_EXECUTE_READWRITE;
	BOOL  status     = FALSE;
	LONG  FunOfset   = NULL;
	ULONG NumberOfBytesToProtect = (ULONG)HANDSIZE;
	PVOID ProtAddress;
	ProtAddress = FunhanderCode_ptr.WinApiStart_ptr;
	//��ȡ���պ�����ַ
	FunOfset = (LONG)FunhanderCode_ptr.HookApi_ptr - (LONG)FunhanderCode_ptr.WinApiStart_ptr - HANDSIZE;
	//PAGE_EXECUTE_READWRITE  Windows Server 2003��Windows XP����Windows XP SP2��Windows Server 2003 SP   ��֧��
	if (mdZwProtectVirtualMemory(GetCurrentProcess(), &ProtAddress, &NumberOfBytesToProtect, PAGE_EXECUTE_READWRITE, &oldProtect) == NULL)
	{
		//��ȡͷ������
 		memcpy_s(FunhanderCode_ptr.pHandlerCode, HANDSIZE, FunhanderCode_ptr.WinApiStart_ptr, HANDSIZE);
		//����Ѿ���hook����ô����
		if ((BYTE)*(FunhanderCode_ptr.pHandlerCode) == 0xE9)
		{
			//׼���ڴ���ת
			FunhanderCode_ptr.WinApiStart_ptr = (PLONG)((LONG)*(PLONG)(FunhanderCode_ptr.pHandlerCode + 1) + (LONG)FunhanderCode_ptr.WinApiStart_ptr + HANDSIZE);
			if (!SetHookFunctionHandlerCode(FunhanderCode_ptr))
			{
				//hook
				FunhanderCode_ptr.WinApiStart_ptr[0] = 0xE9;
				*(PLONG)((LONG)FunhanderCode_ptr.WinApiStart_ptr + 1) = FunOfset;

				SetGangPlank(FunhanderCode_ptr);

				//��ԭҳ����
				ProtAddress = FunhanderCode_ptr.WinApiStart_ptr;
				mdZwProtectVirtualMemory(GetCurrentProcess(), &ProtAddress, &NumberOfBytesToProtect, oldProtect, &newProtect);
				status = TRUE;
				return status;
			}
			return  status;
		}
		//hook
		FunhanderCode_ptr.WinApiStart_ptr[0] = 0xE9;
		*(PLONG)((LONG)FunhanderCode_ptr.WinApiStart_ptr + 1) = FunOfset;

		SetGangPlank(FunhanderCode_ptr);

		//��ԭҳ����
		ProtAddress = FunhanderCode_ptr.WinApiStart_ptr;
		mdZwProtectVirtualMemory(GetCurrentProcess(), &ProtAddress, &NumberOfBytesToProtect, oldProtect, &newProtect);
		status = TRUE;
		return status;
	}
	return status;
}

//�쳣����
LONG WINAPI ExceptionHandle(_EXCEPTION_POINTERS *excp_pointer)
{
	DWORD wByteNum = 0;
	WCHAR DeskPath[MAX_PATH] = { 0 };
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE h_PieceFile = NULL;
	OBJECT_ATTRIBUTES oaName = { 0 };
	UNICODE_STRING usFileName = { 0 };
	IO_STATUS_BLOCK    iosBlock = { 0 };

	for (int num = 0 ;num < MAX_MEMINFO; num++)
	{
		//�����ǿ��õ�
		if (MDTListMemInfo[num].log == TRUE)
			continue;

		if ((MDTListMemInfo[num].MemSize + (ULONG)MDTListMemInfo[num].pMemStart) > excp_pointer->ContextRecord->Eip && (ULONG)MDTListMemInfo[num].pMemStart <= excp_pointer->ContextRecord->Eip)
		{
			//д�ļ�
			wsprintfW(DeskPath, L"\\??\\%s\\%x.dmp", g_DumpPath, MDTListMemInfo[num].pMemStart);
			mdRtlInitUnicodeString(&usFileName,DeskPath);
			InitializeObjectAttributes(&oaName,
				&usFileName,
				OBJ_CASE_INSENSITIVE,
				NULL,
				NULL);
			mdZwCreateFile(&h_PieceFile, FILE_GENERIC_WRITE,&oaName,&iosBlock,NULL,FILE_ATTRIBUTE_NORMAL,NULL, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT,NULL, 0);

			MessageBoxA(0, "fsdafdsfa", "fasdfadsf", 0);
			//��ȡ��ִ�д���
			mdZwWriteFile(h_PieceFile, NULL,NULL,NULL, &iosBlock,MDTListMemInfo[num].pMemStart, MDTListMemInfo[num].MemSize, NULL, NULL);
			mdZwClose(h_PieceFile);

			PVOID tmpStart = MDTListMemInfo[num].pMemStart;
			ULONG tmpSize = MDTListMemInfo[num].MemSize;

			MDTListMemInfo[num].log = TRUE;
			//����Ϊ��ִ��
			if (mdZwProtectVirtualMemory(GetCurrentProcess(), &tmpStart, &tmpSize, MDTListMemInfo[num].Protect, &wByteNum) == 0)
			{
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			
			return EXCEPTION_CONTINUE_SEARCH;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

//���庯��
VOID SetGangPlank(MDTFunInfo& FunhanderCode_ptr)
{
	LONG FunOffset = 0;

	//��ȡ���庯���Ŀ�ʼ
	FunhanderCode_ptr.GangPlank_ptr = (LONG*)((LONG)GangPlank_ptr);
	GangPlank_ptr = (PLONG)((LONG)GangPlank_ptr + 10);

	//��ԭ���ߵĴ���
	memcpy_s(FunhanderCode_ptr.GangPlank_ptr, HANDSIZE, FunhanderCode_ptr.pHandlerCode, HANDSIZE);

	//�������
	FunOffset = (LONG)FunhanderCode_ptr.WinApiStart_ptr - ((LONG)FunhanderCode_ptr.GangPlank_ptr + 5);

	//jmp��ԭʼ����
	*(BYTE*)((LONG)FunhanderCode_ptr.GangPlank_ptr + HANDSIZE) = 0xE9;
	*(LONG*)((LONG)FunhanderCode_ptr.GangPlank_ptr + HANDSIZE + 1) = FunOffset;
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
	LONG  num = 0;
	oZwAllocateVirtualMemory = (tZwAllocateVirtualMemory)(MDTListFunInfo[0].GangPlank_ptr);
	
	//�������Ѿ��ύ��ҳ��  ������������
	//if (AllocationType == MEM_COMMIT)
	//�����ǵ�ǰ����
	if (off == TRUE && EXCEPTIONSIZE < *(PLONG)RegionSize && ProcessHandle == GetCurrentProcess())
	{
		//����ǿ�ִ��������ô�͸���Ϊ����ִ��
		if (Protect == PAGE_EXECUTE || Protect == PAGE_EXECUTE_READWRITE || Protect == PAGE_EXECUTE_READ || Protect == PAGE_EXECUTE_WRITECOPY)
		{
			for (; num < MAX_MEMINFO; num++)
			{
				if (MDTListMemInfo[num].log == TRUE)
					break;
			}
			MDTListMemInfo[num].log = FALSE;
			//�����ڴ���Ϣ
			MDTListMemInfo[num].Protect = Protect;
			//���ı�������
			Protect = PAGE_READWRITE;

			//���庯��
			status = oZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
			MDTListMemInfo[num].MemSize = *(PLONG)RegionSize;
			MDTListMemInfo[num].pMemStart = (PLONG)*BaseAddress;
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
	LONG  num = 0;

	tZwProtectVirtualMemory oZwProtectVirtualMemory = nullptr;
	oZwProtectVirtualMemory = (tZwProtectVirtualMemory)(MDTListFunInfo[1].GangPlank_ptr);

	if (off == TRUE && EXCEPTIONSIZE < *(PLONG)NumberOfBytesToProtect &&  ProcessHandle == GetCurrentProcess())
	{
		if (NewAccessProtection == PAGE_EXECUTE || NewAccessProtection == PAGE_EXECUTE_READWRITE || NewAccessProtection == PAGE_EXECUTE_READ || NewAccessProtection == PAGE_EXECUTE_WRITECOPY)
		{

			for (; num < MAX_MEMINFO; num++)
			{
				if (MDTListMemInfo[num].log == TRUE)
					break;
			}
			MDTListMemInfo[num].log = FALSE;

			//�����ڴ���Ϣ
			MDTListMemInfo[num].Protect = NewAccessProtection;
			//���ı�������
			NewAccessProtection = PAGE_READWRITE;
			status = oZwProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

			MDTListMemInfo[num].pMemStart = (PLONG)*BaseAddress;
			MDTListMemInfo[num].MemSize = *(PLONG)NumberOfBytesToProtect;
			
			return status;
		}
	}
	status = oZwProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	return status;
}