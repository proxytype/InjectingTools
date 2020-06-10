using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace dllinject
{
    public class SetWindowHook
    {

        IntPtr ptrPayload = IntPtr.Zero;
        IntPtr ptrPayloadFunc = IntPtr.Zero;

        public enum HookType : uint
        {
            WH_JOURNALRECORD = 0,
            WH_JOURNALPLAYBACK = 1,
            WH_KEYBOARD = 2,
            WH_GETMESSAGE = 3,
            WH_CALLWNDPROC = 4,
            WH_CBT = 5,
            WH_SYSMSGFILTER = 6,
            WH_MOUSE = 7,
            WH_HARDWARE = 8,
            WH_DEBUG = 9,
            WH_SHELL = 10,
            WH_FOREGROUNDIDLE = 11,
            WH_CALLWNDPROCRET = 12,
            WH_KEYBOARD_LL = 13,
            WH_MOUSE_LL = 14
        }


        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr module, string functionName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("user32.dll")]
        public static extern IntPtr SetWindowsHookEx(HookType code, IntPtr func, IntPtr hInstance, int threadID);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool UnhookWindowsHookEx(IntPtr hhk);

        public void makeHook(HookType hook, string payloadPath, string payloadFunc)
        {
            ptrPayload = LoadLibrary(payloadPath);
            if (ptrPayload != IntPtr.Zero)
            {
                ptrPayloadFunc = GetProcAddress(ptrPayload, payloadFunc);

                if (ptrPayloadFunc != IntPtr.Zero)
                {
                    SetWindowsHookEx(hook, ptrPayloadFunc, ptrPayload, 0);
                }
                else
                {
                    destroyHook();
                }
            }
            else
            {
                destroyHook();
            }

        }

        public void destroyHook()
        {
            if (ptrPayload != IntPtr.Zero)
            {
                UnhookWindowsHookEx(ptrPayload);
            }
        }

    }
}
