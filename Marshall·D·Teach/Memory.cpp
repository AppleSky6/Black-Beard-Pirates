#include "stdafx.h"
#include "_global.h"
#include "Memory.h"


//https://docs.microsoft.com/zh-cn/windows/desktop/Memory/memory-protection-constants 页保护属性常量
//获取页属性
BOOL GetMemInfo(SIZE_T Address, MEMORY_BASIC_INFORMATION& mic)
{
	SIZE_T tpAddress = Address;
	//整数对齐
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