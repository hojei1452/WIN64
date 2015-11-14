// x64.InjectDll.cpp : 콘솔 응용 프로그램에 대한 진입점을 정의합니다.
//

#include "stdafx.h"

BOOL Inject(DWORD pid, char *szDllName)
{
	printf("pid : %d\n", pid);
	printf("dll : %s\n", szDllName);

	HANDLE hProc;
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProc == NULL)
	{
		errorLOG("OpenProcess()");
		return FALSE;
	}

	TCHAR szProcessName[MAX_PATH];
	if (GetModuleFileNameExW(hProc, NULL, szProcessName, MAX_PATH) == 0)
	{
		errorLOG("GetModuleFileNameExW()");
		return FALSE;
	}
	wprintf(TEXT("path : %s\n"), szProcessName);

	PCHAR pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)strlen(szDllName) + 1;
	pRemoteBuf = (PCHAR)VirtualAllocEx(hProc, NULL, dwBufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
	{
		errorLOG("VirtualAllocEx()");
		return FALSE;
	}

	SIZE_T cbWritten = 0;
	if (WriteProcessMemory(hProc, pRemoteBuf, szDllName, strlen(szDllName), &cbWritten) == FALSE)
	{
		errorLOG("WriteProcessMemory()");
		return FALSE;
	}

	HMODULE kernel32_handle = GetModuleHandleW(TEXT("kernel32.dll"));
	LPTHREAD_START_ROUTINE load_library_ptr;
	load_library_ptr = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32_handle, "LoadLibraryA");
	if (load_library_ptr == NULL)
	{
		errorLOG("GetProcAddress()");
		return FALSE;
	}

	HANDLE remote_thread;
	remote_thread = CreateRemoteThreadEx(hProc, NULL, 0, load_library_ptr, pRemoteBuf, NULL, NULL, NULL);
	if (remote_thread == NULL)
	{
		errorLOG("CreateRemoteThreadEx()"); 
		return FALSE;
	}

	if (WaitForSingleObject(remote_thread, INFINITE) == WAIT_FAILED)
	{
		errorLOG("WaitForSingleObject()");
		return FALSE;
	}

	if (!VirtualFreeEx(hProc, pRemoteBuf, dwBufSize, MEM_DECOMMIT))
	{
		errorLOG("VirtualFreeEx()");
		return FALSE;
	}

	if (!CloseHandle(hProc))
	{
		errorLOG("CloseHandle()");
		return FALSE;
	}

	return TRUE;

}

BOOL Eject(DWORD pid, LPCSTR szDllName)
{
	printf("pid : %d\n", pid);
	printf("dll : %s\n", szDllName);

	WCHAR * szDllPath;
	DWORD strSize = MultiByteToWideChar(CP_ACP, 0, szDllName, -1, NULL, NULL);
	szDllPath = new WCHAR[strSize];
	MultiByteToWideChar(CP_ACP, 0, szDllName, (DWORD)strlen(szDllName) + 1, szDllPath, strSize);

	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot;
	MODULEENTRY32 me = { sizeof(me) };

	if (INVALID_HANDLE_VALUE == (hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)))
	{
		errorLOG("CreateToolhelp32Snapshot()");
		return FALSE;
	}
		
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (!_wcsicmp(me.szModule, szDllPath) || !_wcsicmp(me.szExePath, szDllPath))
		{
			bFound = TRUE;
			break;
		}
	}

	if (!bFound)
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	HANDLE hProcess;
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)))
	{
		errorLOG("OpenProcess()");

		CloseHandle(hSnapshot);
		if (!CloseHandle(hProcess))
		{
			errorLOG("CloseHandle()");
			return FALSE;
		}
		return FALSE;
	}

	TCHAR szProcessName[MAX_PATH];
	if (GetModuleFileNameExW(hProcess, NULL, szProcessName, MAX_PATH) == 0)
	{
		errorLOG("GetModuleFileNameExW()");
		return FALSE;
	}
	wprintf(TEXT("path : %s\n"), szProcessName);

	LPTHREAD_START_ROUTINE pThreadProc;
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "FreeLibrary");
	if (pThreadProc == NULL)
	{
		errorLOG("GetProcAddress()");
		return FALSE;
	}

	HANDLE remote_thread;
	remote_thread = CreateRemoteThreadEx(hProcess, NULL, 0, pThreadProc, me.modBaseAddr, 0, NULL, NULL);
	if (remote_thread == NULL)
	{
		errorLOG("CreateRemoteThreadEx()");
		return FALSE;
	}

	if (WaitForSingleObject(remote_thread, INFINITE) == WAIT_FAILED)
	{
		errorLOG("WaitForSingleObject()");
		return FALSE;
	}

	if (!CloseHandle(remote_thread))
	{
		errorLOG("CloseHandle()");
		return FALSE;
	}

	if (!CloseHandle(hProcess))
	{
		errorLOG("CloseHandle()");
		return FALSE;
	}

	if (!CloseHandle(hSnapshot))
	{
		errorLOG("CloseHandle()");
		return FALSE;
	}

	return TRUE;
}

int _tmain(int argc, _TCHAR *argv[])
{
	_wsetlocale(LC_ALL, TEXT("korean"));

	if (argc != 4)
	{
		wprintf(TEXT("   usage : %s <-inject|-eject> <pid> <dll_fullpath>\n"), argv[0]);
		wprintf(TEXT(" example : %s -inject 1234 c:\\mydll\\example.dll\n"), argv[0]);
		return -1;
	}

	if (SetPrivilege(SE_DEBUG_NAME, TRUE) == FALSE)
	{
		errorLOG("SetPrivilege()");
		return -1;
	}

	char *szDllName;
	int strSize = WideCharToMultiByte(CP_ACP, 0, argv[3], -1, NULL, 0, NULL, NULL);
	szDllName = new char[strSize];
	WideCharToMultiByte(CP_ACP, 0, argv[3], -1, szDllName, strSize, 0, 0);

	DWORD pid;
	TCHAR *pEnd;
	pid = wcstol(argv[2], &pEnd, 10);

	if (!_wcsicmp(argv[1], TEXT("-inject")))
	{
		if (Inject(pid, szDllName) == FALSE)
		{
			errorLOG("injection()");
			return -1;
		}
	}

	if (!_wcsicmp(argv[1], TEXT("-eject")))
	{
		if (Eject(pid, szDllName) == FALSE)
		{
			errorLOG("Eject()");
			return -1;
		}
	}

	return 0;
}

