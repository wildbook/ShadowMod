#pragma once

#include <iostream>
#include <windows.h>
#include <cstdint>
#include <cstddef>

namespace IAT
{
    inline auto find(const char* function, HMODULE module) -> void**
    {
        if (module == nullptr)
            module = GetModuleHandle(nullptr);

        const auto p_img_dos_headers = PIMAGE_DOS_HEADER(module);
        const auto p_img_nt_headers  = PIMAGE_NT_HEADERS(LPBYTE(p_img_dos_headers) + p_img_dos_headers->e_lfanew);
        const auto p_img_import_desc = PIMAGE_IMPORT_DESCRIPTOR(LPBYTE(p_img_dos_headers) + p_img_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].
            VirtualAddress);
        
        if (p_img_dos_headers->e_magic != IMAGE_DOS_SIGNATURE)
        {
            printf("e_magic is no valid DOS signature\n");
            return nullptr;
        }

        for (auto* iid = p_img_import_desc; iid->Name != NULL; iid++) {
            for (auto func_idx = 0; *(func_idx + reinterpret_cast<LPVOID*>(iid->FirstThunk + SIZE_T(module))) != nullptr; func_idx++) {
                const auto mod_func_name = reinterpret_cast<char*>(*(func_idx + reinterpret_cast<SIZE_T*>(iid->OriginalFirstThunk + SIZE_T(module))) + SIZE_T(module) + 2);
                if (!_stricmp(function, mod_func_name))
                    return func_idx + reinterpret_cast<LPVOID*>(iid->FirstThunk + SIZE_T(module));
            }
        }

        return nullptr;
    }

    template<class TTypeDef>
    auto hook(const char* function, void* new_function, HMODULE module = nullptr) -> TTypeDef
    {
        auto&& func_ptr = find(function, module);

        if (!func_ptr)
            return 0;

        if (*func_ptr == new_function || *func_ptr == nullptr)
            return 0;

        DWORD old_rights, new_rights = PAGE_READWRITE;
        VirtualProtect(func_ptr, sizeof(LPVOID), new_rights, &old_rights);
        auto ret = uintptr_t(*func_ptr);
        *func_ptr = new_function;
        VirtualProtect(func_ptr, sizeof(LPVOID), old_rights, &new_rights);
        return TTypeDef(ret);
    }
};