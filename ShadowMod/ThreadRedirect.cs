using System;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using ShadowMod.Native;

namespace ShadowMod
{
    public class ThreadRedirect
    {
        public static int Inject64(IntPtr hProcess, IntPtr hThread, string dllName)
        {
            // Get thread context
            var tContext = new CONTEXT64 { ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL };

            // Get current thread context, from here we can get where we're currently executing code (RIP)
            if (NativeMethods.GetThreadContext(hThread, ref tContext))
                Console.WriteLine($"CurrentEip   : 0x{tContext.Rip:X}");

            // Create an array containing our shellcode
            var shellCode = new byte[]
            {
                // Push all registers to save state
                0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x9C,

                // Save rsp and setup stack for function call
                0x53,                   //push   rbx
                0x48, 0x89, 0xe3,       //mov    rbx,rsp
                0x48, 0x83, 0xec, 0x20, //sub    rsp,0x20
                0x66, 0x83, 0xe4, 0xc0, //and    sp,0xffc0
           
                // Call LoadLibraryA
                0x48, 0xb9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //movabs rcx,0xCCCCCCCCCCCCCCCC | Pointer to our dll we want to "inject"
                0x48, 0xba, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //movabs rdx,0xCCCCCCCCCCCCCCCC | Pointer to LoadLibraryA
                0xff, 0xd2,                                                 //call   rdx

                // Save return value so we can access it
                0x48, 0xba, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //movabs rdx,0xCCCCCCCCCCCCCCCC | Pointer to where to save the return value
                0x48, 0x89, 0x02,                                           //mov    QWORD PTR [rdx],rax

                // Fix stack
                0x48, 0x89, 0xdc, //mov    rsp,rbx
                0x5b,             //pop    rbx
            
                // Pop all registers from the stack
                0x9D, 0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58,

                // Jump back to the where the thread was when we hijacked it
                0x48, 0xbb, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //movabs rbx,0xCCCCCCCCCCCCCCCC | Pointer to original thread RIP
                0xff, 0xe3,                                                 //jmp rbx
            
                // Return value from LoadLibraryA ends up here
                0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            };

            // Get the name of the dll we want to inject
            var dllString = Encoding.ASCII.GetBytes(dllName);

            // Add that dll name to the end of the payload so we can read it from within the payload
            var payload = new byte[shellCode.Length + dllString.Length];
            shellCode.CopyTo(payload, 0);
            dllString.CopyTo(payload, shellCode.Length);

            // Allocate memory for shellcode within process
            var allocMemAddress = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, ((payload.Length + 1) * Marshal.SizeOf(typeof(char))), AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE, MemoryProtection.PAGE_EXECUTE_READWRITE);
            var ownProcess = new IntPtr(-1);

            // Try to get the Kernel32 module for our own process
            // This works as Windows has this dll based at the same location for all processes
            // See: http://www.nynaeve.net/?p=198
            if (!ProcessExtensions.GetModule(ownProcess, "Kernel32", out var k32))
                throw new Win32Exception();

            // Find where LoadLibraryA is in our process, it will be at the same location in the target process as well
            var functions = ProcessExtensions.GetExportedFunctions(ownProcess, k32);
            var loadLibraryPtr = functions.First(x => x.Name == "LoadLibraryA").Address;

            // Calculate the other variables we need to insert into our shellcode
            var returnValuePtr = allocMemAddress + 81;
            var dllStringPtr   = allocMemAddress + 89;
            var returnToPtr    = tContext.Rip;

            // Insert all values we got into the right place in the shellcode, overwriting the existing 0xCC addresses
            BitConverter.GetBytes(dllStringPtr.ToInt64())  .CopyTo(payload, 23);
            BitConverter.GetBytes(loadLibraryPtr.ToInt64()).CopyTo(payload, 33);
            BitConverter.GetBytes(returnValuePtr.ToInt64()).CopyTo(payload, 45);
            BitConverter.GetBytes(returnToPtr)             .CopyTo(payload, 71);

            // Write shellcode within process
            NativeMethods.WriteProcessMemory(hProcess, allocMemAddress, payload, (uint)((payload.Length + 1) * Marshal.SizeOf(typeof(char))), out UIntPtr bytesWritten);

            // Read memory to view shellcode
            var bytesRead = 0;
            var buffer = new byte[payload.Length];
            NativeMethods.ReadProcessMemory(hProcess, allocMemAddress, buffer, buffer.Length, ref bytesRead);

            // Set context EIP to location of shellcode
            tContext.Rip = (ulong)allocMemAddress.ToInt64();

            // Apply new context to suspended thread
            if (!NativeMethods.SetThreadContext(hThread, ref tContext))
            {
                Console.WriteLine("Error setting context");
            }

            // Get thread context again, just to log it and be sure we modified it correctly
            // For debugging purposes only, not needed
            if (NativeMethods.GetThreadContext(hThread, ref tContext))
            {
                Console.WriteLine($"Payload Address : {allocMemAddress:X}");
                Console.WriteLine($"NewEip          : {tContext.Rip:X}");
            }

            //TODO: Read return value from LoadLibrary
            Console.WriteLine("TI: Done.");
            return 0;
        }
    }
}