#include "stdafx.h"
#include "Hook.h"

pMDTFunInfo		MDTListFunInfo[10]				= { 0 };
std::vector<pmdzMemDumpInfo>	MDTListMemInfo;
wchar_t			g_DumpPath[MAX_PATH]			= { 0 };
PLONG			GangPlank_ptr					= nullptr;
LONG			GangPlankSize					= NULL;

//hook前信息的初始化
BOOL HookInit()
{
	HWND	hwdDeskDir			= NULL;
	wchar_t DeskPath[MAX_PATH]	= { 0 };

	//为hook函数信息结构体数组指针初始化
	for (int i = 0; i <= 10; i++)
	{
		pMDTFunInfo mdt = new MDTFunInfo;
		MDTListFunInfo[i] = mdt;
	}

	//获取桌面路径文件路径
	SHGetSpecialFolderPath(0, DeskPath, CSIDL_DESKTOPDIRECTORY, 0);
	wsprintfW(g_DumpPath, L"%s\\%s", DeskPath, DUMPFOLDE);

	//如果不存在的话创建
	//if(ERROR_FILE_EXISTS == SHCreateDirectory(hwdDeskDir, wcWrokPath))
	SHCreateDirectory(hwdDeskDir, g_DumpPath);

	//制作跳板
	GangPlank_ptr = (PLONG)VirtualAlloc(NULL, GangPlankSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (GangPlank_ptr == NULL)
	{
		return FALSE;
	}
	memset(GangPlank_ptr, 0x90, GangPlankSize);
	return TRUE;
}

//获取hook处位置和代码
BOOL SetHookFunctionHandlerCode(pMDTFunInfo FunhanderCode_ptr)
{
	DWORD oldProtect = NULL;
	DWORD newProtect = NULL;
	BOOL  status     = FALSE;
	LONG  FunOfset   = NULL;

	//获取最终函数地址
	FunOfset = (LONG)FunhanderCode_ptr->HookApi_ptr - (LONG)FunhanderCode_ptr->WinApiStart_ptr - HANDSIZE;
	MessageBox(0, L"-----------------", L"------------", 0);
	//PAGE_EXECUTE_READWRITE  Windows Server 2003和Windows XP：在Windows XP SP2和Windows Server 2003 SP   不支持
	if (VirtualProtect(FunhanderCode_ptr->WinApiStart_ptr, HANDSIZE, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		//获取头部代码
		memcpy_s(FunhanderCode_ptr->pHandlerCode, HANDSIZE, FunhanderCode_ptr->WinApiStart_ptr, HANDSIZE);
		//如果已经被hook了那么跟进
		if (FunhanderCode_ptr->pHandlerCode[0] == 0xE9)
		{
			//准备在此跳转
			FunhanderCode_ptr->WinApiStart_ptr = (PLONG)(FunhanderCode_ptr->pHandlerCode);
			if (SetHookFunctionHandlerCode(FunhanderCode_ptr))
			{
				//hook
				FunhanderCode_ptr->WinApiStart_ptr[0] = 0xE9;
				*(PLONG)((LONG)FunhanderCode_ptr->WinApiStart_ptr + 1) = FunOfset;

				SetGangPlank(FunhanderCode_ptr);

				//还原页保护
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

		//还原页保护
		VirtualProtect(FunhanderCode_ptr->WinApiStart_ptr, HANDSIZE, oldProtect, &newProtect);
		status = TRUE;
		return status;
	}
	return status;
}

//异常处理
LONG WINAPI ExceptionHandle(_EXCEPTION_POINTERS *excp_pointer)
{
	char* codebuf = nullptr;
	wchar_t PiecePath[MAX_PATH];
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE h_PieceFile = NULL;
	DWORD wByteNum = 0;

	for (auto tmp : MDTListMemInfo)
	{
		if ((tmp->MemSize + (LONG)tmp->pMemStart) > excp_pointer->ContextRecord->Eip && (LONG)tmp->pMemStart <= excp_pointer->ContextRecord->Eip)
		{
			//写文件
			wsprintfW(PiecePath, L"%s\\%x.dmp", g_DumpPath, DUMPFOLDE, (PDWORD)(excp_pointer->ContextRecord->Esp));
			h_PieceFile = CreateFile(PiecePath, GENERIC_WRITE, NULL, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (h_PieceFile == INVALID_HANDLE_VALUE)
			{
				return EXCEPTION_CONTINUE_SEARCH;
			}
			//获取可执行代码
			//使用ReadProcessMemory为了方式该内存突然被释放
			codebuf = new char[tmp->MemSize + 1];
			ReadProcessMemory(GetCurrentProcess(), tmp->pMemStart, codebuf, tmp->MemSize, NULL);

			if (!WriteFile(h_PieceFile, codebuf, tmp->MemSize, &wByteNum, NULL))
			{
				delete codebuf;
				CloseHandle(h_PieceFile);
				return EXCEPTION_CONTINUE_SEARCH;
			}
			delete codebuf;
			CloseHandle(h_PieceFile);

			//更改为可执行
			if (VirtualProtect(tmp->pMemStart, tmp->MemSize, tmp->Protect, &wByteNum) == 0)
			{
				return EXCEPTION_CONTINUE_SEARCH;
			}
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	
	return EXCEPTION_CONTINUE_SEARCH;
}

//跳板函数
VOID SetGangPlank(pMDTFunInfo FunhanderCode_ptr)
{
	LONG FunOffset = 0;

	//获取跳板函数的开始
	FunhanderCode_ptr->GangPlank_ptr = (LONG*)((LONG)GangPlank_ptr);
	GangPlank_ptr = (PLONG)((LONG)GangPlank_ptr + 10);

	//还原扣走的代码
	memcpy_s(FunhanderCode_ptr->GangPlank_ptr, HANDSIZE, FunhanderCode_ptr->pHandlerCode, HANDSIZE);

	//计算距离
	FunOffset = (LONG)FunhanderCode_ptr->WinApiStart_ptr - ((LONG)FunhanderCode_ptr->GangPlank_ptr + 5);

	//jmp到原始函数
	*(char*)((LONG)FunhanderCode_ptr->GangPlank_ptr + HANDSIZE) = 0xE9;
	*(LONG*)((LONG)FunhanderCode_ptr->GangPlank_ptr + HANDSIZE + 1) = FunOffset;
}

//hook ZwAllocateVirtualMemory 回调函数
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

	oZwAllocateVirtualMemory = (tZwAllocateVirtualMemory)(MDTListFunInfo[0]->GangPlank_ptr);

	//必须是已经提交的页面
	if (AllocationType == MEM_COMMIT)
	{
		//如果是可执行属性那么就更改为不可执行
		if (Protect == PAGE_EXECUTE || Protect == PAGE_EXECUTE_READWRITE || Protect == PAGE_EXECUTE_READ || Protect == PAGE_EXECUTE_WRITECOPY)
		{
			pmdzMemDumpInfo tmpInfo = nullptr;
			tmpInfo = new mdzMemDumpInfo;
			//保存内存信息
			tmpInfo->Protect = Protect;
			//更改保护类型
			Protect = PAGE_READWRITE;

			//备份返回地址
			tmpStart = (PLONG)BaseAddress;
			tmpSize  = (PLONG)RegionSize;
			//跳板函数
			oZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
			tmpInfo->MemSize = *tmpSize;
			tmpInfo->pMemStart = (PLONG)*BaseAddress;
			MDTListMemInfo.push_back(tmpInfo);
			return 0;
		}	
	}
	//更改函数到跳板函数
	oZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	return 0;
}

