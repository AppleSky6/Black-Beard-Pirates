#include <windows.h>

bool(*pf)();
unsigned char shellcode[] = {
0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3
};

void main()
{
	LoadLibrary("Marshall��D��Teach.dll");
	char* pByte = (char*)VirtualAlloc(0x1d0000, 1024, MEM_COMMIT, PAGE_READWRITE);
	memset(pByte, 0, 1024);
	memcpy_s(pByte, 1000, shellcode, 6);
	_asm{
		call pByte;
	}
	MessageBox(0, "fasdfa", "fsadfasdf", 0);
}
