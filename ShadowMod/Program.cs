using Microsoft.Win32;
using ShadowMod;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace SimpleDebugger
{
    internal static class Program
    {
        private const string TargetProcessName = "Risk of Rain 2.exe";

        private static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                //AllocConsole();

                var app = args[0];
                var cmdLine = string.Empty;
                if (args.Length > 1)
                    cmdLine = $"\"{args.Skip(1).Aggregate((x, y) => $"{x}\" \"{y}")}\"";

                StartProcess(app, cmdLine);

                Console.WriteLine("Injected.");
                Console.ReadLine();
            }
            else
            {
                Menu();
            }
        }

        private static void StartProcess(string app, string cmdLine)
        {
            var sInfo = new STARTUPINFO();

            if (!CreateProcess(app, cmdLine, IntPtr.Zero, IntPtr.Zero, false, 2 + 4, IntPtr.Zero, null, ref sInfo, out var pInfo))
                throw new Win32Exception();

            Console.WriteLine("Suspended.");
            DebugActiveProcessStop(pInfo.dwProcessId);

            ThreadHijack.Inject(pInfo.hProcess, pInfo.hThread, "thing.dll");

            // Resume the thread, redirecting execution to shellcode, then back to original process
            Console.WriteLine("Redirecting execution!");

            SuspendedProcess.Resume(pInfo.hThread);
            Console.WriteLine("Running.");
        }

        private static void Menu()
        {
            AllocConsole();

            RegistryKey registryKey = null;
            var location = Assembly.GetExecutingAssembly().Location;
            try
            {
                registryKey =
                    Registry.LocalMachine.CreateSubKey(
                        @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" +
                        TargetProcessName);
            }
            catch (UnauthorizedAccessException)
            {
                try
                {
                    new Process
                    {
                        StartInfo =
                        {
                            FileName = Assembly.GetExecutingAssembly().Location,
                            UseShellExecute = true,
                            Verb = "runas"
                        }
                    }.Start();
                    Environment.Exit(0);
                }
                catch
                {
                    Console.WriteLine("Access denied.");
                    Thread.Sleep(1000);
                    Environment.Exit(1);
                }
            }

            var selected = 0;
            const int maxSelected = 2;

            while (true)
            {
                Console.Clear();
                Console.ResetColor();
                Console.CursorVisible = false;
                Console.Write("Currently hooked to: ");

                var hookedTo = (registryKey?.GetValue("debugger") ?? "Nothing.").ToString()
                    .Replace(location, "This program.");

                if (hookedTo == "This program.")
                    Console.ForegroundColor = ConsoleColor.Green;
                else if (hookedTo != "Nothing.")
                    Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(hookedTo);

                if (selected == 0) Console.ForegroundColor = ConsoleColor.White;
                else Console.ResetColor();
                Console.WriteLine($"{(selected == 0 ? "-->" : "   ")} Register {TargetProcessName} debugger IEFO.");

                if (selected == 1) Console.ForegroundColor = ConsoleColor.White;
                else Console.ResetColor();
                Console.WriteLine($"{(selected == 1 ? "-->" : "   ")} Unregister {TargetProcessName} debugger IEFO.");

                if (selected == 2) Console.ForegroundColor = ConsoleColor.White;
                else Console.ResetColor();
                Console.WriteLine($"{(selected == 2 ? "-->" : "   ")} Exit.");

                var redraw = false;
                while (!redraw)
                    switch (Console.ReadKey(true).Key)
                    {
                        case ConsoleKey.UpArrow:
                            if (selected != (selected = Math.Max(selected - 1, 0)))
                                redraw = true;
                            break;

                        case ConsoleKey.DownArrow:
                            if (selected != (selected = Math.Min(selected + 1, maxSelected)))
                                redraw = true;
                            break;

                        case ConsoleKey.Enter:
                            redraw = true;
                            switch (selected)
                            {
                                case 0:
                                    registryKey?.SetValue("debugger", location);
                                    break;

                                case 1:
                                    registryKey?.DeleteValue("debugger");
                                    break;

                                case 2:
                                    Environment.Exit(0);
                                    break;
                            }
                            break;
                    }
            }
        }

        #region Windows API

        // ReSharper disable All

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AllocConsole();

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DebugActiveProcessStop([In] int Pid);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        private struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum DebugEventType
        {
            EXCEPTION_DEBUG_EVENT      = 1, //Reports an exception debugging event. The value of u.Exception specifies an EXCEPTION_DEBUG_INFO structure.
            CREATE_THREAD_DEBUG_EVENT  = 2, //Reports a create-thread debugging event. The value of u.CreateThread specifies a CREATE_THREAD_DEBUG_INFO structure.
            CREATE_PROCESS_DEBUG_EVENT = 3, //Reports a create-process debugging event. The value of u.CreateProcessInfo specifies a CREATE_PROCESS_DEBUG_INFO structure.
            EXIT_THREAD_DEBUG_EVENT    = 4, //Reports an exit-thread debugging event. The value of u.ExitThread specifies an EXIT_THREAD_DEBUG_INFO structure.
            EXIT_PROCESS_DEBUG_EVENT   = 5, //Reports an exit-process debugging event. The value of u.ExitProcess specifies an EXIT_PROCESS_DEBUG_INFO structure.
            LOAD_DLL_DEBUG_EVENT       = 6, //Reports a load-dynamic-link-library (DLL) debugging event. The value of u.LoadDll specifies a LOAD_DLL_DEBUG_INFO structure.
            UNLOAD_DLL_DEBUG_EVENT     = 7, //Reports an unload-DLL debugging event. The value of u.UnloadDll specifies an UNLOAD_DLL_DEBUG_INFO structure.
            OUTPUT_DEBUG_STRING_EVENT  = 8, //Reports an output-debugging-string debugging event. The value of u.DebugString specifies an OUTPUT_DEBUG_STRING_INFO structure.
            RIP_EVENT                  = 9, //Reports a RIP-debugging event (system debugging error). The value of u.RipInfo specifies a RIP_INFO structure.
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DEBUG_EVENT
        {
            public readonly DebugEventType dwDebugEventCode;
            public readonly int dwProcessId;
            public readonly int dwThreadId;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 86, ArraySubType = UnmanagedType.U1)]
            private readonly byte[] debugInfo;
        }

        // ReSharper restore All

        #endregion Windows API
    }
}