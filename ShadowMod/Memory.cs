using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using ShadowMod.Exceptions;
using ShadowMod.Native;

namespace ShadowMod
{
    public class Memory : IDisposable
    {
        private static readonly char[] _zero = { (char)0 };
        private readonly IntPtr _processHandle;
        private readonly List<(IntPtr Pointer, int Size)> _allocations = new List<(IntPtr Pointer, int Size)>();

        public Memory(Process process) => _processHandle = process.Handle;
        public Memory(IntPtr processHandle) => _processHandle = processHandle;

        public string ReadString(IntPtr address, int length, Encoding encoding)
        {
            var str = encoding.GetString(ReadBytes(address, length), 0, length);
            str = str.Split(_zero, 2).First();
            return str;
        }

        public string ReadUnicodeString(IntPtr address, int length) => Encoding.Unicode.GetString(ReadBytes(address, length));
        public short ReadShort(IntPtr address) => BitConverter.ToInt16(ReadBytes(address, 2), 0);
        public int ReadInt(IntPtr address) => BitConverter.ToInt32(ReadBytes(address, 4), 0);
        public long ReadLong(IntPtr address) => BitConverter.ToInt64(ReadBytes(address, 8), 0);
        public IntPtr ReadInt32Ptr(IntPtr address) => (IntPtr)BitConverter.ToInt32(ReadBytes(address, 4), 0);
        public IntPtr ReadInt64Ptr(IntPtr address) => (IntPtr)BitConverter.ToInt64(ReadBytes(address, 8), 0);

        public byte[] ReadBytes(IntPtr address, int size)
        {
            var bytes = new byte[size];
            if (!NativeMethods.ReadProcessMemory(_processHandle, address, bytes, size))
                throw new FailedToReadMemoryException(new Win32Exception(Marshal.GetLastWin32Error()));
            return bytes;
        }

        public IntPtr AllocateAndWrite(byte[] data)
        {
            var address = Allocate(data.Length);
            Write(address, data);
            return address;
        }

        public IntPtr AllocateAndWrite(string data) => AllocateAndWrite(Encoding.UTF8.GetBytes(data));
        public IntPtr AllocateAndWrite(int data) => AllocateAndWrite(BitConverter.GetBytes(data));
        public IntPtr AllocateAndWrite(long data) => AllocateAndWrite(BitConverter.GetBytes(data));

        public IntPtr Allocate(int size)
        {
            var addr = NativeMethods.VirtualAllocEx(_processHandle, IntPtr.Zero, size, AllocationType.MEM_COMMIT, MemoryProtection.PAGE_EXECUTE_READWRITE);
            if (addr == IntPtr.Zero)
                throw new MemoryException("Failed to allocate process memory", new Win32Exception(Marshal.GetLastWin32Error()));
            _allocations.Add((addr, size));
            return addr;
        }

        public void Write(IntPtr addr, byte[] data)
        {
            if (!NativeMethods.WriteProcessMemory(_processHandle, addr, data, data.Length))
                throw new FailedToWriteMemoryException(new Win32Exception(Marshal.GetLastWin32Error()));
        }

        public void Dispose()
        {
            foreach (var (pointer, size) in _allocations)
                NativeMethods.VirtualFreeEx(_processHandle, pointer, size, MemoryFreeType.MEM_DECOMMIT);
        }
    }
}
