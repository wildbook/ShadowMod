// dllmain.cpp : Defines the entry point for the DLL application.

// Exclude rarely-used stuff from Windows headers
#define WIN32_LEAN_AND_MEAN
// Windows Header Files
#include <windows.h>

#include <cstdio>
#include <iostream>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
        printf("Hello, from a DLL injected before the process initialized.\nOne step closer.\n\n");
        printf("\n");

        // Somewhere in here we hook CreateFileW or ReadFile to redirect to our own modded file
        // Currently the program also executes async to this (I think?), need to look into race condition, will fix
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

