#include <iostream>
#include "Windows.h"
#include <UserEnv.h>
#include <WtsApi32.h>
#include <Tlhelp32.h>
#include <Tchar.h>
#include <string>
#pragma comment(lib,"WtsApi32.lib")
#pragma comment(lib,"UserEnv.lib")

using ::std::cout;
using ::std::endl;

BOOL LaunchApplication(LPCWSTR Filename) {
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    BOOL bResult = FALSE;
    DWORD dwSessionId, winlogonPid = 0;
    HANDLE hUserToken = NULL, hUserTokenDup = NULL, hPToken = NULL, hProcess = NULL;
    DWORD dwCreationFlags;
    LPVOID pEnv = NULL;
    wchar_t* w_desk = NULL;
    bool winlogonFound = false;

    /* Log the client on to the local computer. */
    dwSessionId = WTSGetActiveConsoleSessionId();

    /* Find the winlogon process */
    PROCESSENTRY32 procEntry;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    procEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnap, &procEntry)) {
        CloseHandle(hSnap);
        return FALSE;
    }

    do {
        /* szExeFile is already a (wide) string under the Unicode charset,
           so compare it directly instead of converting it by hand. */
        if (_wcsicmp(procEntry.szExeFile, L"winlogon.exe") == 0) {
            // We found a winlogon process...
            // make sure it's running in the console session
            DWORD winlogonSessId = 0;
            if (ProcessIdToSessionId(procEntry.th32ProcessID, &winlogonSessId)
                && winlogonSessId == dwSessionId)
            {
                winlogonPid = procEntry.th32ProcessID;
                winlogonFound = true;
                break;
            }
        }

    } while (Process32Next(hSnap, &procEntry));

    CloseHandle(hSnap);

    if (!winlogonFound) {
        printf("winlogon.exe not found in the active console session\n");
        return FALSE;
    }

    if (!WTSQueryUserToken(dwSessionId, &hUserToken)) {
        printf("WTSQueryUserToken: %u\n", GetLastError());
        return FALSE;
    }

    dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    const char* desk = "Winsta0\\Default";
    size_t size = strlen(desk) + 1;
    w_desk = new wchar_t[size];
    size_t outSize;
    mbstowcs_s(&outSize, w_desk, size, desk, size - 1);

    si.lpDesktop = w_desk;
    ZeroMemory(&pi, sizeof(pi));
    TOKEN_PRIVILEGES tp;
    LUID luid;
    hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, winlogonPid);

    if (hProcess == NULL) {
        printf("OpenProcess: %u\n", GetLastError());
        delete[] w_desk;
        CloseHandle(hUserToken);
        return FALSE;
    }

    if (!::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
        | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID
        | TOKEN_READ | TOKEN_WRITE, &hPToken))
    {
        printf("OpenProcessToken: %u\n", GetLastError());
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("LookupPrivilegeValue: %u\n", GetLastError());
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL,
        SecurityIdentification, TokenPrimary, &hUserTokenDup);

    //Adjust Token privilege
    SetTokenInformation(hUserTokenDup,
        TokenSessionId, (void*)&dwSessionId, sizeof(DWORD));

    if (!AdjustTokenPrivileges(hUserTokenDup, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL, NULL))
    {
        printf("AdjustTokenPrivileges: %u\n", GetLastError());
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("Token does not have the provilege\n");
    }

    if (CreateEnvironmentBlock(&pEnv, hUserTokenDup, TRUE)) {
        dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
    }
    else
        pEnv = NULL;

    /* Launch the process in the client's logon session. */

    bResult = CreateProcessAsUser(
        hUserTokenDup,              // client's access token
        Filename,                   // file to execute
        NULL,                       // command line
        NULL,                       // pointer to process SECURITY_ATTRIBUTES
        NULL,                       // pointer to thread SECURITY_ATTRIBUTES
        FALSE,                      // handles are not inheritable
        dwCreationFlags,            // creation flags
        pEnv,                       // pointer to new environment block
        NULL,                       // name of current directory
        &si,                        // pointer to STARTUPINFO structure
        &pi                         // receives information about new process
    );
    /* End impersonation of client */

    if (!bResult) {
        printf("CreateProcessAsUser: %u\n", GetLastError());
    }

    /* Perform All the Close Handles tasks */

    if (pEnv) DestroyEnvironmentBlock(pEnv);
    delete[] w_desk;
    if (bResult) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(hProcess);
    CloseHandle(hUserToken);
    if (hUserTokenDup) CloseHandle(hUserTokenDup);
    if (hPToken) CloseHandle(hPToken);

    return bResult;
}

int main(int argc, const char* argv[])
try {
    if (!LaunchApplication(L"C:\\ru1smake\\ru1smakehelper.exe"))
    {
        cout << "Launch failed" << endl;
        return 1;
    }

    cout << "Done!" << endl;
}
catch (std::exception& ex) {
    cout << "STD EXCEPTION: " << ex.what() << endl;
    return 1;
}
catch (const char* ex) {
    cout << "EXCEPTION: " << ex << endl;
    return 1;
}
