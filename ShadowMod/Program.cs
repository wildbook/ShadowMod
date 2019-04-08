using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;
using ShadowMod.Native;

namespace ShadowMod
{
    internal static class Program
    {
        private const string TargetProcessName = "Risk of Rain 2.exe";

        private static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                var app = args[0];
                var cmdLine = string.Empty;
                if (args.Length > 1)
                    cmdLine = $"\"{args.Skip(1).Aggregate((x, y) => $"{x}\" \"{y}")}\"";

                StartProcess(app, cmdLine);
                Console.WriteLine("Injected.");
            }
            else
            {
                Menu();
            }
        }

        private static void StartProcess(string app, string cmdLine)
        {
            var sInfo = new STARTUPINFO();

            if (!NativeMethods.CreateProcess(app, cmdLine, IntPtr.Zero, IntPtr.Zero, false, 2 + 4, IntPtr.Zero, null, ref sInfo, out var pInfo))
                throw new Win32Exception();

            NativeMethods.DebugActiveProcessStop(pInfo.dwProcessId);
            ThreadRedirect.Inject64(pInfo.hProcess, pInfo.hThread, "ShadowMod.Internal.dll");
            NativeMethods.ResumeThread(pInfo.hThread);
        }

        private static void Menu()
        {
            NativeMethods.AllocConsole();

            RegistryKey registryKey = null;
            var location = Assembly.GetExecutingAssembly().Location;
            try
            {
                registryKey = Registry.LocalMachine.CreateSubKey($@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{TargetProcessName}");
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
                {
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
        }
    }
}