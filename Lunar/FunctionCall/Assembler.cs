using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Lunar.FunctionCall.Structures;

namespace Lunar.FunctionCall
{
    internal static class Assembler
    {
        internal static byte[] AssembleCallDescriptor(CallDescriptor callDescriptor)
        {
            var assembledBytes = new List<byte>();

            if (callDescriptor.IsWow64Call)
            {
                if (callDescriptor.CallingConvention == CallingConvention.FastCall)
                {
                    // Move the first parameter into the ECX register

                    if (callDescriptor.Parameters.Length > 0)
                    {
                        var parameter = callDescriptor.Parameters[0];

                        if (parameter == 0)
                        {
                            // xor ecx, ecx

                            assembledBytes.AddRange(new byte[] {0x31, 0xC9});
                        }

                        else
                        {
                            // mov ecx, parameter

                            assembledBytes.Add(0xB9);

                            assembledBytes.AddRange(BitConverter.GetBytes((int) parameter));
                        }
                    }

                    // Move the second parameter into the EDX register

                    if (callDescriptor.Parameters.Length > 1)
                    {
                        var parameter = callDescriptor.Parameters[1];

                        if (parameter == 0)
                        {
                            // xor edx, edx

                            assembledBytes.AddRange(new byte[] {0x31, 0xD2});
                        }

                        else
                        {
                            // mov edx, parameter

                            assembledBytes.Add(0xBA);

                            assembledBytes.AddRange(BitConverter.GetBytes((int) parameter));
                        }
                    }

                    // Push the remaining parameters onto the stack in reverse order

                    if (callDescriptor.Parameters.Length > 2)
                    {
                        foreach (var parameter in callDescriptor.Parameters[2..].Reverse())
                        {
                            if (parameter <= sbyte.MaxValue)
                            {
                                // push parameter

                                assembledBytes.AddRange(new byte[] {0x6A, (byte) parameter});
                            }

                            else
                            {
                                // push parameter

                                assembledBytes.Add(0x68);

                                assembledBytes.AddRange(BitConverter.GetBytes((int) parameter));
                            }
                        }
                    }
                }

                else
                {
                    // Push each parameter onto the stack in reverse order

                    foreach (var parameter in callDescriptor.Parameters.Reverse())
                    {
                        if (parameter <= sbyte.MaxValue)
                        {
                            // push parameter

                            assembledBytes.AddRange(new byte[] {0x6A, (byte) parameter});
                        }

                        else
                        {
                            // push parameter

                            assembledBytes.Add(0x68);

                            assembledBytes.AddRange(BitConverter.GetBytes((int) parameter));
                        }
                    }
                }

                // mov eax, address

                assembledBytes.Add(0xB8);

                assembledBytes.AddRange(BitConverter.GetBytes(callDescriptor.Address.ToInt32()));

                // call eax

                assembledBytes.AddRange(new byte[] {0xFF, 0xD0});

                // mov [returnAddress], eax

                assembledBytes.Add(0xA3);

                assembledBytes.AddRange(BitConverter.GetBytes(callDescriptor.ReturnAddress.ToInt32()));
            }

            else
            {
                // sub rsp, 0x28

                assembledBytes.AddRange(new byte[] {0x48, 0x83, 0xEC, 0x28});

                // Move the first parameter into the RCX register

                if (callDescriptor.Parameters.Length > 0)
                {
                    var parameter = callDescriptor.Parameters[0];

                    if (parameter == 0)
                    {
                        // xor ecx, ecx

                        assembledBytes.AddRange(new byte[] {0x31, 0xC9});
                    }

                    else
                    {
                        if (parameter <= int.MaxValue)
                        {
                            // mov ecx, parameter

                            assembledBytes.Add(0xB9);

                            assembledBytes.AddRange(BitConverter.GetBytes((int) parameter));
                        }

                        else
                        {
                            // mov rcx, parameter

                            assembledBytes.AddRange(new byte[] {0x48, 0xB9});

                            assembledBytes.AddRange(BitConverter.GetBytes(parameter));
                        }
                    }
                }

                // Move the second parameter into the RDX register

                if (callDescriptor.Parameters.Length > 1)
                {
                    var parameter = callDescriptor.Parameters[1];

                    if (parameter == 0)
                    {
                        // xor edx, edx

                        assembledBytes.AddRange(new byte[] {0x31, 0xD2});
                    }

                    else
                    {
                        if (parameter <= int.MaxValue)
                        {
                            // mov edx, parameter

                            assembledBytes.Add(0xBA);

                            assembledBytes.AddRange(BitConverter.GetBytes((int) parameter));
                        }

                        else
                        {
                            // mov rdx, parameter

                            assembledBytes.AddRange(new byte[] {0x48, 0xBA});

                            assembledBytes.AddRange(BitConverter.GetBytes(parameter));
                        }
                    }
                }

                // Move the third parameter into the R8 register

                if (callDescriptor.Parameters.Length > 2)
                {
                    var parameter = callDescriptor.Parameters[2];

                    if (parameter == 0)
                    {
                        // xor r8, r8

                        assembledBytes.AddRange(new byte[] {0x4D, 0x31, 0xC0});
                    }

                    else
                    {
                        if (parameter <= int.MaxValue)
                        {
                            // mov r8, parameter

                            assembledBytes.AddRange(new byte[] {0x49, 0xC7, 0xC0});

                            assembledBytes.AddRange(BitConverter.GetBytes((int) parameter));
                        }

                        else
                        {
                            // mov r8, parameter

                            assembledBytes.AddRange(new byte[] {0x49, 0xB8});

                            assembledBytes.AddRange(BitConverter.GetBytes(parameter));
                        }
                    }
                }

                // Move the fourth parameter into the R9 register

                if (callDescriptor.Parameters.Length > 3)
                {
                    var parameter = callDescriptor.Parameters[3];

                    if (parameter == 0)
                    {
                        // xor r9, r9

                        assembledBytes.AddRange(new byte[] {0x4D, 0x31, 0xC9});
                    }

                    else
                    {
                        if (parameter <= int.MaxValue)
                        {
                            // mov r9, parameter

                            assembledBytes.AddRange(new byte[] {0x49, 0xC7, 0xC1});

                            assembledBytes.AddRange(BitConverter.GetBytes((int) parameter));
                        }

                        else
                        {
                            // mov r9, parameter

                            assembledBytes.AddRange(new byte[] {0x49, 0xB9});

                            assembledBytes.AddRange(BitConverter.GetBytes(parameter));
                        }
                    }
                }

                // Push the remaining parameters onto the stack in reverse order

                if (callDescriptor.Parameters.Length > 4)
                {
                    foreach (var parameter in callDescriptor.Parameters[4..].Reverse())
                    {
                        if (parameter <= sbyte.MaxValue)
                        {
                            // push parameter

                            assembledBytes.AddRange(new byte[] {0x6A, (byte) parameter});
                        }

                        else
                        {
                            if (parameter <= int.MaxValue)
                            {
                                // push parameter

                                assembledBytes.Add(0x68);

                                assembledBytes.AddRange(BitConverter.GetBytes((int) parameter));
                            }

                            else
                            {
                                // mov rax, parameter

                                assembledBytes.AddRange(new byte[] {0x48, 0xB8});

                                assembledBytes.AddRange(BitConverter.GetBytes(parameter));

                                // push rax

                                assembledBytes.Add(0x50);
                            }
                        }
                    }
                }

                // mov rax, address

                assembledBytes.AddRange(new byte[] {0x48, 0xB8});

                assembledBytes.AddRange(BitConverter.GetBytes(callDescriptor.Address.ToInt64()));

                // call rax

                assembledBytes.AddRange(new byte[] {0xFF, 0xD0});

                // mov [returnAddress], rax

                assembledBytes.AddRange(new byte[] {0x48, 0xA3});

                assembledBytes.AddRange(BitConverter.GetBytes(callDescriptor.ReturnAddress.ToInt64()));

                // add rsp, 0x28

                assembledBytes.AddRange(new byte[] {0x48, 0x83, 0xC4, 0x28});
            }

            // ret

            assembledBytes.Add(0xC3);

            return assembledBytes.ToArray();
        }
    }
}