﻿using System;

namespace ShadowMod.Native
{
    [Flags]
    public enum MemoryProtection
    {
        PAGE_NOACCESS          = 0x1,
        PAGE_READONLY          = 0x2,
        PAGE_READWRITE         = 0x4,
        PAGE_WRITECOPY         = 0x8,
        PAGE_EXECUTE           = 0x10,
        PAGE_EXECUTE_READ      = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
        PAGE_EXECUTE_WRITECOPY = 0x80,
        PAGE_GUARD             = 0x100,
        PAGE_NOCACHE           = 0x200,
        PAGE_WRITECOMBINE      = 0x400,
        PAGE_TARGETS_INVALID   = 0x40000000,
        PAGE_TARGETS_NO_UPDATE = 0x40000000,
    }
}