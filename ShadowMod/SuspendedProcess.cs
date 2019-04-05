using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShadowMod
{
    class SuspendedProcess
    {
        public IntPtr ThreadHandle { get; private set; }
        public IntPtr ProcessHandle { get; }
        public uint ProcessID { get; }
        public uint ThreadID { get; }
        public Process Process => Process.GetProcessById((int)ProcessID);

        public SuspendedProcess(string binary, string commandline)
        {
            STARTUPINFO startupInfo = new STARTUPINFO();
            bool success = NativeMethods.CreateProcess(
                binary,
                commandline,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                ProcessCreationFlags.CREATE_SUSPENDED | ProcessCreationFlags.DEBUG_ONLY_THIS_PROCESS,
                IntPtr.Zero,
                null,
                ref startupInfo,
                out var processInfo);

            ThreadHandle  = processInfo.hThread;
            ProcessHandle = processInfo.hProcess;
            ProcessID     = processInfo.dwProcessId;
            ThreadID      = processInfo.dwThreadId;

            if (!success)
                throw new Exception("//TODO: Blame Wildbook");
        }

        public void Resume()
        {
            NativeMethods.ResumeThread(ThreadHandle);
        }

        public static void Resume(IntPtr threadHandle)
        {
            NativeMethods.ResumeThread(threadHandle);
        }
    }
}
