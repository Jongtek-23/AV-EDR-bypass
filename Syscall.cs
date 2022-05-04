using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

using static SharpCall.Native;

namespace SharpCall
{
    public class Syscall
    {
        static byte[] bNtOpenProcess10 = { 0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        static byte[] bNtCreateThreadEx = { 0x4C, 0x8B, 0xD1, 0xB8, 0xC1, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        static byte[] bNtAllocateVirtualMemory = { 0x4C, 0x8B, 0xD1, 0xb8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        static byte[] bNtWriteVirtualMemory = { 0x4C, 0x8B, 0xD1, 0xB8, 0x3A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

        public static NTSTATUS NTOpenProcess10(ref IntPtr ProcessHandle, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID ClientId)
        {
            byte[] syscall = bNtOpenProcess10;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Native.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.ZwOpenProcess myAssemblyFunction = (Delegates.ZwOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwOpenProcess));

                    return (NTSTATUS)myAssemblyFunction(out ProcessHandle, processAccess, objAttribute, ref ClientId);
                }
            }
        }

        public static NTSTATUS NtCreateThreadEx10(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, int inCreateSuspended, uint stackZeroBits, uint sizeOfStack, uint maximumStackSize, IntPtr attributeList)
        {
            byte[] syscall = bNtCreateThreadEx;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Native.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtCreateThreadEx myAssemblyFunction = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateThreadEx));
                
                    return (NTSTATUS)myAssemblyFunction(out threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, inCreateSuspended, stackZeroBits, sizeOfStack, maximumStackSize, attributeList);
                }
            }
        }

        public static NTSTATUS NtAllocateVirtualMemory10(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect)
        {
            byte[] syscall = bNtAllocateVirtualMemory;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Native.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtAllocateVirtualMemory myAssemblyFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
                }
            }
        }

        public static NTSTATUS NtWriteVirtualMemory10(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint NumberOfBytesToWrite, ref IntPtr NumberOfBytesWritten)
        {
            byte[] syscall = bNtWriteVirtualMemory;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Native.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtWriteVirtualMemory myAssemblyFunction = (Delegates.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtWriteVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, ref NumberOfBytesWritten);
                }
            }
        }


        public struct Delegates
        {
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint NumberOfBytesToWrite, ref IntPtr NumberOfBytesWritten);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, int inCreateSuspended, uint stackZeroBits, uint sizeOfStack, uint maximumStackSize, IntPtr attributeList);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwOpenProcess(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int LdrLoadDll(IntPtr PathToFile,
                UInt32 dwFlags,
                ref Native.UNICODE_STRING ModuleFileName,
                ref IntPtr ModuleHandle);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);


        }
    }
}
