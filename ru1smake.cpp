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

void convertWStringToCharPtr(_In_ std::wstring input, _Out_ char* outputString)
{
    size_t outputSize = input.length() + 1; // +1 for null terminator
    outputString = new char[outputSize];
    size_t charsConverted = 0;
    const wchar_t* inputW = input.c_str();
    wcstombs_s(&charsConverted, outputString, outputSize, inputW, input.length());
}

BOOL LaunchApplication(LPCWSTR Filename)
{
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    BOOL bResult = FALSE;
    DWORD dwSessionId, winlogonPid;
    HANDLE hUserToken, hUserTokenDup, hPToken, hProcess;
    DWORD dwCreationFlags;

    // Log the client on to the local computer.
    dwSessionId = WTSGetActiveConsoleSessionId();

    // Find the winlogon process
    PROCESSENTRY32 procEntry;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    procEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnap, &procEntry))
    {
        return 1;
    }

    do
    {
        char exeFile[13] = "winlogon.exe";
        convertWStringToCharPtr(procEntry.szExeFile, exeFile);
        const char* cExeFile = exeFile;

        if (_stricmp(cExeFile, "winlogon.exe") == 0)
        {
            // We found a winlogon process...
            // make sure it's running in the console session
            DWORD winlogonSessId = 0;
            if (ProcessIdToSessionId(procEntry.th32ProcessID, &winlogonSessId)
                && winlogonSessId == dwSessionId)
            {
                winlogonPid = procEntry.th32ProcessID;
                break;
            }
        }

    } while (Process32Next(hSnap, &procEntry));


    WTSQueryUserToken(dwSessionId, &hUserToken);
    dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    const char* desk = "Winsta0\\Default";
    size_t size = strlen(desk) + 1;
    wchar_t* w_desk = new wchar_t[size];
    size_t outSize;
    mbstowcs_s(&outSize, w_desk, size, desk, size - 1);

    si.lpDesktop = w_desk;
    ZeroMemory(&pi, sizeof(pi));
    TOKEN_PRIVILEGES tp;
    LUID luid;
    hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, winlogonPid);

    if (!::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
        | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID
        | TOKEN_READ | TOKEN_WRITE, &hPToken))
    {
        printf("OpenProcessToken: %u\n", GetLastError());
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        printf("LookupPrivilegeValue: %u\n", GetLastError());
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL,
        SecurityIdentification, TokenPrimary, &hUserTokenDup);

    //Adjust Token privilege
    SetTokenInformation(hUserTokenDup,
        TokenSessionId, (void*)dwSessionId, sizeof(DWORD));

    if (!AdjustTokenPrivileges(hUserTokenDup, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL, NULL))
    {
        printf("AdjustTokenPrivileges: %u\n", GetLastError());
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("Token does not have the provilege\n");
    }

    LPVOID pEnv = NULL;

    if (CreateEnvironmentBlock(&pEnv, hUserTokenDup, TRUE))
    {
        dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
    }
    else
        pEnv = NULL;

    // Launch the process in the client's logon session.

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
    // End impersonation of client.

    //GetLastError Shud be 0

    int iResultOfCreateProcessAsUser = GetLastError();

    //Perform All the Close Handles tasks

    CloseHandle(hProcess);
    CloseHandle(hUserToken);
    CloseHandle(hUserTokenDup);
    CloseHandle(hPToken);

    return 0;
}

int main(int argc, const char* argv[])
try {
    LaunchApplication(L"C:\\ru1smake\\ru1smakehelper.exe");
    
    cout << "Done!" << endl;
}
catch (std::exception& ex)
{
    cout << "STD EXCEPTION: " << ex.what() << endl;
    return 1;
}
catch (const char* ex)
{
    cout << "EXCEPTION: " << ex << endl;
    return 1;
}