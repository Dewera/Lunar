using System;
using System.Collections.Generic;
using Lunar.Assembler.Structures;
using Lunar.Extensions;

namespace Lunar.Assembler
{
    internal static class RoutineAssembler
    {
        internal static Span<byte> AssembleRoutine32(RoutineDescriptor routineDescriptor)
        {
            var routineInstructions = new List<byte>();

            for (var parameterIndex = routineDescriptor.Parameters.Count - 1; parameterIndex >= 0; parameterIndex -= 1)
            {
                var parameter = (int) routineDescriptor.Parameters[parameterIndex];

                if (parameter <= sbyte.MaxValue)
                {
                    // push parameter

                    routineInstructions.AddRange(stackalloc byte[] {0x6A, (byte) parameter});
                }

                else
                {
                    // push parameter

                    routineInstructions.Add(0x68);

                    routineInstructions.AddRange(BitConverter.GetBytes(parameter));
                }
            }

            // mov eax, address

            routineInstructions.Add(0xB8);

            routineInstructions.AddRange(BitConverter.GetBytes(routineDescriptor.Address.ToInt32()));

            // call eax

            routineInstructions.AddRange(stackalloc byte[] {0xFF, 0xD0});

            if (routineDescriptor.ReturnBuffer != IntPtr.Zero)
            {
                // mov [returnBuffer], eax

                routineInstructions.Add(0xA3);

                routineInstructions.AddRange(BitConverter.GetBytes(routineDescriptor.ReturnBuffer.ToInt32()));
            }

            // xor eax, eax

            routineInstructions.AddRange(stackalloc byte[] {0x33, 0xC0});

            // ret

            routineInstructions.Add(0xC3);

            return routineInstructions.ToArray();
        }

        internal static Span<byte> AssembleRoutine64(RoutineDescriptor routineDescriptor)
        {
            var routineInstructions = new List<byte>();

            // sub rsp, 0x28

            routineInstructions.AddRange(stackalloc byte[] {0x48, 0x83, 0xEC, 0x28});

            for (var parameterIndex = 0; parameterIndex < routineDescriptor.Parameters.Count; parameterIndex += 1)
            {
                var parameter = (long) routineDescriptor.Parameters[parameterIndex];

                switch (parameterIndex)
                {
                    case 0:
                    {
                        if (parameter == 0)
                        {
                            // xor ecx, ecx

                            routineInstructions.AddRange(stackalloc byte[] {0x31, 0xC9});
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

                            routineInstructions.AddRange(stackalloc byte[] {0x48, 0xB9});

                            routineInstructions.AddRange(BitConverter.GetBytes(parameter));
                        }

                        break;
                    }

                    case 1:
                    {
                        if (parameter == 0)
                        {
                            // xor edx, edx

                            routineInstructions.AddRange(stackalloc byte[] {0x31, 0xD2});
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

                            routineInstructions.AddRange(stackalloc byte[] {0x48, 0xBA});

                            routineInstructions.AddRange(BitConverter.GetBytes(parameter));
                        }

                        break;
                    }

                    case 2:
                    {
                        if (parameter == 0)
                        {
                            // xor r8d, r8d

                            routineInstructions.AddRange(stackalloc byte[] {0x45, 0x31, 0xC0});
                        }

                        else if (parameter <= uint.MaxValue)
                        {
                            // mov r8d, parameter

                            routineInstructions.AddRange(stackalloc byte[] {0x41, 0xB8});

                            routineInstructions.AddRange(BitConverter.GetBytes((int) parameter));
                        }

                        else
                        {
                            // mov r8, parameter

                            routineInstructions.AddRange(stackalloc byte[] {0x49, 0xB8});

                            routineInstructions.AddRange(BitConverter.GetBytes(parameter));
                        }

                        break;
                    }

                    case 3:
                    {
                        if (parameter == 0)
                        {
                            // xor r9d, r9d

                            routineInstructions.AddRange(stackalloc byte[] {0x45, 0x31, 0xC9});
                        }

                        else if (parameter <= uint.MaxValue)
                        {
                            // mov r9d, parameter

                            routineInstructions.AddRange(stackalloc byte[] {0x41, 0xB9});

                            routineInstructions.AddRange(BitConverter.GetBytes((int) parameter));
                        }

                        else
                        {
                            // mov r9, parameter

                            routineInstructions.AddRange(stackalloc byte[] {0x49, 0xB9});

                            routineInstructions.AddRange(BitConverter.GetBytes(parameter));
                        }

                        break;
                    }
                }
            }

            // mov rax, address

            routineInstructions.AddRange(stackalloc byte[] {0x48, 0xB8});

            routineInstructions.AddRange(BitConverter.GetBytes(routineDescriptor.Address.ToInt64()));

            // call rax

            routineInstructions.AddRange(stackalloc byte[] {0xFF, 0xD0});

            if (routineDescriptor.ReturnBuffer != IntPtr.Zero)
            {
                // mov [returnBuffer], rax

                routineInstructions.AddRange(stackalloc byte[] {0x48, 0xA3});

                routineInstructions.AddRange(BitConverter.GetBytes(routineDescriptor.ReturnBuffer.ToInt64()));
            }

            // xor eax, eax

            routineInstructions.AddRange(stackalloc byte[] {0x31, 0xC0});

            // add rsp, 0x28

            routineInstructions.AddRange(stackalloc byte[] {0x48, 0x83, 0xC4, 0x28});

            // ret

            routineInstructions.Add(0xC3);

            return routineInstructions.ToArray();
        }
    }
}