#include "stdafx.h"



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
	wsprintf(c_msg, L"[Dbg]: %s", msg);
	MessageBox(0, c_msg, L"dbg", 0);
}
