#pragma once

#include <iostream>
#include <windows.h>
#include <cstdint>
#include <cstddef>

namespace IAT
{
    auto find(const char* function, HMODULE module) -> void**
    {
        if (module == 0)
            module = GetModuleHandle(0);

        auto pImgDosHeaders = (PIMAGE_DOS_HEADER)module;
        auto pImgNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pImgDosHeaders + pImgDosHeaders->e_lfanew);
        auto pImgImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pImgDosHeaders + pImgNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        
        int size = (int)((LPBYTE)pImgDosHeaders + pImgNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

        if (pImgDosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
        {
            printf("e_magic is no valid DOS signature\n");
            return 0;
        }

        for (auto* iid = pImgImportDesc; iid->Name != NULL; iid++) {
            for (int funcIdx = 0; *(funcIdx + (LPVOID*)(iid->FirstThunk + (SIZE_T)module)) != NULL; funcIdx++) {
                auto modFuncName = (char*)(*(funcIdx + (SIZE_T*)(iid->OriginalFirstThunk + (SIZE_T)module)) + (SIZE_T)module + 2);
                if (!_stricmp(function, modFuncName))
                    return funcIdx + (LPVOID*)(iid->FirstThunk + (SIZE_T)module);
            }
        }

        return 0;
    }

    template<class TTypeDef>
    auto hook(const char* function, void* newfunction, HMODULE module = 0) -> TTypeDef
    {
        auto&& func_ptr = find(function, module);

        if (!func_ptr)
            return 0;

        if (*func_ptr == newfunction || *func_ptr == nullptr)
            return 0;

        DWORD oldrights, newrights = PAGE_READWRITE;
        VirtualProtect(func_ptr, sizeof(LPVOID), newrights, &oldrights);
        uintptr_t ret = (uintptr_t)*func_ptr;
        *func_ptr = newfunction;
        VirtualProtect(func_ptr, sizeof(LPVOID), oldrights, &newrights);
        return TTypeDef(ret);
    }
};