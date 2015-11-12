// x64.myDll.cpp : DLL 응용 프로그램을 위해 내보낸 함수를 정의합니다.
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
