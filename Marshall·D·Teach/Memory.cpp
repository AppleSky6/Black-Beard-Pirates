#include "stdafx.h"
#include "_global.h"
#include "Memory.h"


//https://docs.microsoft.com/zh-cn/windows/desktop/Memory/memory-protection-constants 页保护属性常量
//获取页属性
BOOL GetMemInfo(LONG Address, MEMORY_BASIC_INFORMATION& mic)
{
	MEMORY_BASIC_INFORMATION tq_mic;

	//直接返回
	if (Address < 0x1000)
	{
		return FALSE;
	}

	//整数对齐
	Address = (Address / 0x1000) * 0x1000;

	if (VirtualQuery((PVOID)Address, &mic, sizeof(MEMORY_BASIC_INFORMATION)) != 0)
	{
		if (VirtualQuery((PVOID)(Address - 0x1000), &tq_mic, sizeof(MEMORY_BASIC_INFORMATION)) != 0)
		{
			if (tq_mic.Protect == mic.Protect)
			{
				if (GetMemInfo((Address - 0x1000), mic) == FALSE)
				{
					mic = tq_mic;
					return TRUE;
				}		
			}
			return TRUE;
		}
		return TRUE;
	}
	return FALSE;
}