// stdafx.h : ���� ��������� ���� ��������� �ʴ�
// ǥ�� �ý��� ���� ���� �� ������Ʈ ���� ���� ������
// ��� �ִ� ���� �����Դϴ�.
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>

#include <Windows.h>
#include <locale.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <strsafe.h>

// TODO: ���α׷��� �ʿ��� �߰� ����� ���⿡�� �����մϴ�.

void errorLOG(char *functionName);
BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);