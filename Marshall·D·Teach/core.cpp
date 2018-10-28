#include "stdafx.h"
#include "core.h"


void DbgMsg(SIZE_T msg)
{
	wchar_t c_msg[50];
	memset(c_msg, 0, 50);
	wsprintf(c_msg, L"[Dbg]: %x", msg);
	MessageBox(0, c_msg, L"dbg", 0);
}


void DbgMsg(LPCWSTR msg)
{
	wchar_t c_msg[50];
	memset(c_msg, 0, 50);
	wsprintf(c_msg, L"[Dbg]: %x", msg);
	MessageBox(0, c_msg, L"dbg", 0);
}


//https://docs.microsoft.com/zh-cn/windows/desktop/Memory/memory-protection-constants ҳ�������Գ���
//��ȡҳ����
BOOL GetMemInfo(SIZE_T Address, MEMORY_BASIC_INFORMATION& mic)
{
	SIZE_T tpAddress = Address;
	//��������
	tpAddress = (tpAddress / 0x1000) * 0x1000;
	do 
	{
		if (DWORD dwResult = VirtualQuery((PVOID)Address, &mic, sizeof(MEMORY_BASIC_INFORMATION)) != 0)
			//if (mic.RegionSize + (SIZE_T)mic.BaseAddress > Address && mic.Protect != PAGE_EXECUTE && mic.Protect != PAGE_EXECUTE_READ )
			if (mic.RegionSize + (SIZE_T)mic.BaseAddress > Address)
			{
				DbgMsg(tpAddress);
				return TRUE;
			}	
			else
				return FALSE;
		tpAddress = tpAddress - 0x1000;
	} while (tpAddress > 0);
	return FALSE;
}

LONG WINAPI MyUnhandledExceptionFilter(PEXCEPTION_POINTERS pExInfo)
{
	EXCEPTION_POINTERS ExInfoCopy (*pExInfo);
	MEMORY_BASIC_INFORMATION mic;
	char* codebuf = nullptr;

	wchar_t DeskPath[255];
	wchar_t PiecePath[255];
	SECURITY_ATTRIBUTES sa = {0};
	HANDLE h_PieceFile = NULL;
	DWORD wByteNum = 0;

	//�����ȡ�����쳣�ĵ�ַ�ڴ�����ʧ�ܾ���
	//EXCEPTION_CONTINUE_SEARCH ִ����һ���쳣����EXCEPTION_EXECUTE_HANDLER ����ִ�в����쳣�Ĵ���
	if(!GetMemInfo(ExInfoCopy.ContextRecord->Eip, mic))
		return EXCEPTION_CONTINUE_SEARCH;
/*
	//��ҳ���ǿ�ִ��ҳ��
	if (mic.Protect == PAGE_EXECUTE || mic.Protect == PAGE_EXECUTE_READ)
		return EXCEPTION_CONTINUE_SEARCH;

	//��ȡ��ִ�д���
	//ʹ��ReadProcessMemoryΪ�˷�ʽ���ڴ�ͻȻ���ͷ�
	codebuf = new char[mic.RegionSize + 1];
	ReadProcessMemory(GetCurrentProcess(), mic.BaseAddress, codebuf, mic.RegionSize, NULL);

	//д�ļ�
	SHGetSpecialFolderPath(0, DeskPath, CSIDL_DESKTOPDIRECTORY, 0);
	wsprintfW(PiecePath, L"%s\\%s\\%x.dmp", DeskPath, VIRUSFOLDE,(PDWORD)(ExInfoCopy.ContextRecord->Esp));
	h_PieceFile = CreateFile(PiecePath, GENERIC_WRITE, NULL, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_PieceFile == INVALID_HANDLE_VALUE)
	{
		DbgMsg(L"CreateFile faile");
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if (!WriteFile(h_PieceFile, codebuf, mic.RegionSize, &wByteNum, NULL))
	{
		DbgMsg(L"WriteFile faile");
		CloseHandle(h_PieceFile);
		return EXCEPTION_CONTINUE_SEARCH;
	}


	
	CloseHandle(h_PieceFile);
*/
//����Ϊ��ִ��
	
	if (VirtualProtect(mic.BaseAddress, mic.RegionSize, mic.Protect|PAGE_EXECUTE_READWRITE, &wByteNum) == 0)
	{
		DbgMsg(L"VirtualProtect faile");
	}
	return EXCEPTION_EXECUTE_HANDLER;
}