// dllmain.cpp : DLL 응용 프로그램의 진입점을 정의합니다.
#include "stdafx.h"


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	TCHAR szProcessName[MAX_PATH];
	PTCHAR p = NULL;
	if (GetModuleFileName(NULL, szProcessName, MAX_PATH) == 0)
		return FALSE;

	p = wcsrchr(szProcessName, TEXT('\\'));
	if ((p != NULL) && !_wcsicmp(p + 1, TEXT("x64.GlobalHook.exe")))
		return TRUE;

	if (SetPrivilege(SE_DEBUG_NAME, TRUE) == FALSE)
		return FALSE;

	BYTE bakBytes_CPA[9] = { 0, };
	BYTE bakBytes_CPW[9] = { 0, };
	BYTE bakBytes_NTQ[9] = { 0, };
	
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		enable_code_hooking(TEXT("kernel32.dll"), "CreateProcessA", (PROC)MyCreateProcessA, bakBytes_CPA);
		enable_code_hooking(TEXT("kernel32.dll"), "CreateProcessW", (PROC)MyCreateProcessW, bakBytes_CPW);
		enable_code_hooking(TEXT("ntdll.dll"), "NtQuerySystemInformation", (PROC)MyNtQuerySystemInformation, bakBytes_NTQ);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		disable_code_hooking(TEXT("kernel32.dll"), "CreateProcessA", bakBytes_CPA);
		disable_code_hooking(TEXT("kernel32.dll"), "CreateProcessW", bakBytes_CPW);
		disable_code_hooking(TEXT("ntdll.dll"), "NtQuerySystemInformation", bakBytes_NTQ);
		break;
	}
	return TRUE;
}

