using ShadowMod;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Thunderbolt.Core
{
    public static class ProcessExtensions
    {
        public static IEnumerable<(string Name, IntPtr Address)> GetExportedFunctions(Process process, IntPtr mod)
            => GetExportedFunctions(process.Handle, mod);

        public static IEnumerable<(string Name, IntPtr Address)> GetExportedFunctions(IntPtr handle, IntPtr mod)
        {
            using (var memory = new Memory(handle))
            {
                var e_lfanew        = memory.ReadInt(mod + 0x3C);
                var ntHeaders       = mod + e_lfanew;
                var optionalHeader  = ntHeaders + 0x18;
                var dataDirectory   = optionalHeader + (Is64BitProcess(handle) ? 0x70 : 0x60);
                var exportDirectory = mod + memory.ReadInt(dataDirectory);
                var names           = mod + memory.ReadInt(exportDirectory + 0x20);
                var ordinals        = mod + memory.ReadInt(exportDirectory + 0x24);
                var functions       = mod + memory.ReadInt(exportDirectory + 0x1C);
                var count           = memory.ReadInt(exportDirectory + 0x18);

                for (var i = 0; i < count; i++)
                {
                    var offset  = memory.ReadInt(names + i * 4);
                    var name    = memory.ReadString(mod + offset, 32, Encoding.ASCII);
                    var ordinal = memory.ReadShort(ordinals + i * 2);
                    var address = mod + memory.ReadInt(functions + ordinal * 4);

                    if (address != IntPtr.Zero)
                        yield return (name, address);
                }
            }
        }

        public static bool GetModule(Process process, string name, out IntPtr module)
            => GetModule(process.Handle, name, out module);

        public static bool GetModule(IntPtr handle, string name, out IntPtr module)
        {
            var size = Is64BitProcess(handle) ? 8 : 4;
            var pointers = new IntPtr[0];

            if (!Native.EnumProcessModulesEx(handle, pointers, 0, out var bytesNeeded, ModuleFilter.LIST_MODULES_ALL))
                throw new Exception("Failed to enumerate process modules", new Win32Exception());

            var count = bytesNeeded / size;
            pointers = new IntPtr[count];

            if (!Native.EnumProcessModulesEx(handle, pointers, bytesNeeded, out bytesNeeded, ModuleFilter.LIST_MODULES_ALL))
                throw new Exception("Failed to enumerate process modules", new Win32Exception());

            for (var i = 0; i < count; i++)
            {
                // Microsoft's constant, I didn't just choose one randomly
                const int MAX_PATH = 260;

                var path = new StringBuilder(MAX_PATH);
                Native.GetModuleFileNameEx(handle, pointers[i], path, MAX_PATH);

                if (path.ToString().IndexOf(name, StringComparison.InvariantCultureIgnoreCase) > -1)
                {
                    if (!Native.GetModuleInformation(handle, pointers[i], out var info, (uint)(size * pointers.Length)))
                        throw new Exception("Failed to get module information", new Win32Exception());

                    module = info.lpBaseOfDll;
                    return true;
                }
            }

            module = IntPtr.Zero;
            return false;
        }

        public static bool Is64BitProcess(this Process process) => Is64BitProcess(process.Handle);
        public static bool Is64BitProcess(IntPtr handle)
        {
            if (!Environment.Is64BitOperatingSystem)
                return false;

            if (!Native.IsWow64Process(handle, out var isWow64))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return !isWow64;
        }
    }
}
