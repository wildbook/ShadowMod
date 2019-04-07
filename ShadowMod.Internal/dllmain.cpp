#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include "IAT.h"

typedef HANDLE(__stdcall* fn_CreateFileW) (
    _In_     LPCWSTR               lpFileName,
    _In_     DWORD                 dwDesiredAccess,
    _In_     DWORD                 dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_     DWORD                 dwCreationDisposition,
    _In_     DWORD                 dwFlagsAndAttributes,
    _In_opt_ HANDLE                hTemplateFile
);

fn_CreateFileW oCreateFileW;

HANDLE __stdcall hCreateFileW(
    _In_     LPCWSTR               lpFileName,
    _In_     DWORD                 dwDesiredAccess,
    _In_     DWORD                 dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_     DWORD                 dwCreationDisposition,
    _In_     DWORD                 dwFlagsAndAttributes,
    _In_opt_ HANDLE                hTemplateFile
)
{
    std::wcout << "Loaded file: " << lpFileName << "\n";
    return oCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        freopen_s(reinterpret_cast<FILE * *>(stdout), "CONOUT$", "w", stdout);
        MessageBox(0, L"Hello, and welcome to the magical world of working hooks.", L"FINALLY.", 0);
        oCreateFileW = IAT::hook<fn_CreateFileW>("CreateFileW", &hCreateFileW, GetModuleHandle(L"Kernel32.dll"));


    case DLL_PROCESS_DETACH:
        IAT::hook<fn_CreateFileW>("CreateFileW", &oCreateFileW, GetModuleHandle(L"Kernel32.dll"));
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}