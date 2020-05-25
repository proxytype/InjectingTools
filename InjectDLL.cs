using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace dllinject
{
    public class InjectDLL
    {

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int address, bool inheritHandle, int pid);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string module);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr module, string functionName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr pid, IntPtr address,
            uint size, uint allocationType, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
            IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        //Process Flags
        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;

        //Memory Operation
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;

        public void inject(int pid, string payloadPath) {

            //get requested process pointer
            IntPtr processPtr = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, pid);

            //getting the pointer to LoadLibraryA in kernel32.dll
            IntPtr loadLibraryPtr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            //allocate payload path
            IntPtr allocMemAddress = VirtualAllocEx(processPtr, IntPtr.Zero, (uint)((payloadPath.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            //write to process memory
            UIntPtr bytesWritten;
            WriteProcessMemory(processPtr, allocMemAddress, Encoding.Default.GetBytes(payloadPath), (uint)((payloadPath.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            //create thread in process, execute loadlibrary and call the allocated path
            CreateRemoteThread(processPtr, IntPtr.Zero, 0, loadLibraryPtr, allocMemAddress, 0, IntPtr.Zero);
        }


    }
}
