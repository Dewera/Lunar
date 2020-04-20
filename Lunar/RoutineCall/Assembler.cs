using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Lunar.RoutineCall.Structures;

namespace Lunar.RoutineCall
{
    internal static class Assembler
    {
        internal static ReadOnlyMemory<byte> AssembleRoutine(RoutineDescriptor routineDescriptor)
        {
            var routineInstructions = new List<byte>();

            void AssembleStackParameters(IEnumerable<long> parameters)
            {
                foreach (var parameter in parameters)
                {
                    if (parameter <= sbyte.MaxValue)
                    {
                        // push parameter

                        routineInstructions.AddRange(new byte[] {0x6A, (byte) parameter});
                    }

                    else if (parameter <= uint.MaxValue)
                    {
                        // push parameter

                        routineInstructions.Add(0x68);

                        routineInstructions.AddRange(BitConverter.GetBytes((int) parameter));
                    }

                    else
                    {
                        // mov rax, parameter

                        routineInstructions.AddRange(new byte[] {0x48, 0xB8});

                        routineInstructions.AddRange(BitConverter.GetBytes(parameter));

                        // push rax

                        routineInstructions.Add(0x50);
                    }
                }
            }

            if (routineDescriptor.Architecture == Architecture.X86)
            {
                if (routineDescriptor.CallingConvention == CallingConvention.FastCall)
                {
                    if (routineDescriptor.Parameters.Length > 0)
                    {
                        var parameter = routineDescriptor.Parameters[0];

                        if (parameter == 0)
                        {
                            // xor ecx, ecx

                            routineInstructions.AddRange(new byte[] {0x31, 0xC9});
                        }

                        else
                        {
                            // mov ecx, parameter

                            routineInstructions.Add(0xB9);

                            routineInstructions.AddRange(BitConverter.GetBytes((int) parameter));
                        }
                    }

                    if (routineDescriptor.Parameters.Length > 1)
                    {
                        var parameter = routineDescriptor.Parameters[1];

                        if (parameter == 0)
                        {
                            // xor edx, edx

                            routineInstructions.AddRange(new byte[] {0x31, 0xD2});
                        }

                        else
                        {
                            // mov edx, parameter

                            routineInstructions.Add(0xBA);

                            routineInstructions.AddRange(BitConverter.GetBytes((int) parameter));
                        }
                    }

                    if (routineDescriptor.Parameters.Length > 2)
                    {
                        AssembleStackParameters(routineDescriptor.Parameters[2..]);
                    }
                }

                else
                {
                    AssembleStackParameters(routineDescriptor.Parameters);
                }

                // mov eax, functionAddress

                routineInstructions.Add(0xB8);

                routineInstructions.AddRange(BitConverter.GetBytes(routineDescriptor.FunctionAddress.ToInt32()));

                // call eax

                routineInstructions.AddRange(new byte[] {0xFF, 0xD0});

                // mov [returnBuffer], eax

                routineInstructions.Add(0xA3);

                routineInstructions.AddRange(BitConverter.GetBytes(routineDescriptor.ReturnBuffer.ToInt32()));
            }

            else
            {
                var shadowSpace = routineDescriptor.Parameters.Length > 4 ? (routineDescriptor.Parameters.Length * sizeof(long) + 15) & -16 : 40;

                // sub rsp, shadowSpace

                routineInstructions.AddRange(new byte[] {0x48, 0x83, 0xEC, (byte) shadowSpace});

                if (routineDescriptor.Parameters.Length > 0)
                {
                    var parameter = routineDescriptor.Parameters[0];

                    if (parameter == 0)
                    {
                        // xor ecx, ecx

                        routineInstructions.AddRange(new byte[] {0x31, 0xC9});
                    }

                    else if (parameter <= uint.MaxValue)
                    {
                        // mov ecx, parameter

                        routineInstructions.Add(0xB9);

                        routineInstructions.AddRange(BitConverter.GetBytes((int) parameter));
                    }

                    else
                    {
                        // mov rcx, parameter

                        routineInstructions.AddRange(new byte[] {0x48, 0xB9});

                        routineInstructions.AddRange(BitConverter.GetBytes(parameter));
                    }
                }

                if (routineDescriptor.Parameters.Length > 1)
                {
                    var parameter = routineDescriptor.Parameters[1];

                    if (parameter == 0)
                    {
                        // xor edx, edx

                        routineInstructions.AddRange(new byte[] {0x31, 0xD2});
                    }

                    else if (parameter <= uint.MaxValue)
                    {
                        // mov edx, parameter

                        routineInstructions.Add(0xBA);

                        routineInstructions.AddRange(BitConverter.GetBytes((int) parameter));
                    }

                    else
                    {
                        // mov rdx, parameter

                        routineInstructions.AddRange(new byte[] {0x48, 0xBA});

                        routineInstructions.AddRange(BitConverter.GetBytes(parameter));
                    }
                }

                if (routineDescriptor.Parameters.Length > 2)
                {
                    var parameter = routineDescriptor.Parameters[2];

                    if (parameter == 0)
                    {
                        // xor r8d, r8d

                        routineInstructions.AddRange(new byte[] {0x45, 0x31, 0xC0});
                    }

                    else if (parameter <= uint.MaxValue)
                    {
                        // mov r8d, parameter

                        routineInstructions.AddRange(new byte[] {0x41, 0xB8});

                        routineInstructions.AddRange(BitConverter.GetBytes((int) parameter));
                    }

                    else
                    {
                        // mov r8, parameter

                        routineInstructions.AddRange(new byte[] {0x49, 0xB8});

                        routineInstructions.AddRange(BitConverter.GetBytes(parameter));
                    }
                }

                if (routineDescriptor.Parameters.Length > 3)
                {
                    var parameter = routineDescriptor.Parameters[3];

                    // mov r9, parameter

                    if (parameter == 0)
                    {
                        // xor r9d, r9d

                        routineInstructions.AddRange(new byte[] {0x45, 0x31, 0xC9});
                    }

                    else if (parameter <= uint.MaxValue)
                    {
                        // mov r9d, parameter

                        routineInstructions.AddRange(new byte[] {0x41, 0xB9});

                        routineInstructions.AddRange(BitConverter.GetBytes((int) parameter));
                    }

                    else
                    {
                        // mov r9, parameter

                        routineInstructions.AddRange(new byte[] {0x49, 0xB9});

                        routineInstructions.AddRange(BitConverter.GetBytes(parameter));
                    }
                }

                if (routineDescriptor.Parameters.Length > 4)
                {
                    AssembleStackParameters(routineDescriptor.Parameters[4..]);
                }

                // mov rax, functionAddress

                routineInstructions.AddRange(new byte[] {0x48, 0xB8});

                routineInstructions.AddRange(BitConverter.GetBytes(routineDescriptor.FunctionAddress.ToInt64()));

                // call rax

                routineInstructions.AddRange(new byte[] {0xFF, 0xD0});

                // mov [returnBuffer], rax

                routineInstructions.AddRange(new byte[] {0x48, 0xA3});

                routineInstructions.AddRange(BitConverter.GetBytes(routineDescriptor.ReturnBuffer.ToInt64()));

                // add rsp, shadowSpace

                routineInstructions.AddRange(new byte[] {0x48, 0x83, 0xC4, (byte) shadowSpace});
            }

            // ret

            routineInstructions.Add(0xC3);

            return routineInstructions.ToArray();
        }
    }
}