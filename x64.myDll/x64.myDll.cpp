// x64.myDll.cpp : DLL ���� ���α׷��� ���� ������ �Լ��� �����մϴ�.
//

#include "stdafx.h"


void makeDLL()
{
	STARTUPINFO info = { 0, };
	PROCESS_INFORMATION pi;

	info.cb = sizeof(info);
	SetCurrentDirectory(L"C:\\WINDOWS\\system32");
	CreateProcess(L"calc.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &info, &pi);
}
