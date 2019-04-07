using System;
using System.Runtime.InteropServices;

namespace ShadowMod
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public int SizeOfImage;
        public IntPtr EntryPoint;
    }
}