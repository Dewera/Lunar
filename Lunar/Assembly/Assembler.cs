using System;
using System.Collections.Generic;
using System.Linq;
using Lunar.Assembly.Structures;

namespace Lunar.Assembly
{
    internal static class Assembler
    {
        internal static Span<byte> AssembleCall32(CallDescriptor32 callDescriptor)
        {
            var instructions = new List<byte>();

            foreach (var argument in callDescriptor.Arguments.Reverse())
            {
                if (argument <= sbyte.MaxValue)
                {
                    // push argument

                    instructions.AddRange(new byte[] {0x6A, (byte) argument});
                }

                else
                {
                    // push argument

                    instructions.Add(0x68);

                    instructions.AddRange(BitConverter.GetBytes(argument));
                }
            }

            // mov eax, Address

            instructions.Add(0xB8);

            instructions.AddRange(BitConverter.GetBytes(callDescriptor.Address.ToInt32()));

            // call eax

            instructions.AddRange(new byte[] {0xFF, 0xD0});

            if (callDescriptor.ReturnAddress != IntPtr.Zero)
            {
                // mov ReturnAddress, eax

                instructions.Add(0xA3);

                instructions.AddRange(BitConverter.GetBytes(callDescriptor.ReturnAddress.ToInt32()));
            }

            // xor eax, eax

            instructions.AddRange(new byte[] {0x33, 0xC0});

            // ret

            instructions.Add(0xC3);

            return instructions.ToArray();
        }

        internal static Span<byte> AssembleCall64(CallDescriptor64 callDescriptor)
        {
            var instructions = new List<byte>();

            // sub rsp, 0x28

            instructions.AddRange(new byte[] {0x48, 0x83, 0xEC, 0x28});

            if (callDescriptor.Arguments.Length > 0)
            {
                var argument = callDescriptor.Arguments[0];

                switch (argument)
                {
                    case 0:
                    {
                        // xor ecx, ecx

                        instructions.AddRange(new byte[] {0x31, 0xC9});

                        break;
                    }

                    case <= uint.MaxValue:
                    {
                        // mov ecx, argument

                        instructions.Add(0xB9);

                        instructions.AddRange(BitConverter.GetBytes((int) argument));

                        break;
                    }

                    default:
                    {
                        // mov rcx, argument

                        instructions.AddRange(new byte[] {0x48, 0xB9});

                        instructions.AddRange(BitConverter.GetBytes(argument));

                        break;
                    }
                }
            }

            if (callDescriptor.Arguments.Length > 1)
            {
                var argument = callDescriptor.Arguments[1];

                switch (argument)
                {
                    case 0:
                    {
                        // xor edx, edx

                        instructions.AddRange(new byte[] {0x31, 0xD2});

                        break;
                    }

                    case <= uint.MaxValue:
                    {
                        // mov edx, argument

                        instructions.Add(0xBA);

                        instructions.AddRange(BitConverter.GetBytes((int) argument));

                        break;
                    }

                    default:
                    {
                        // mov rdx, argument

                        instructions.AddRange(new byte[] {0x48, 0xBA});

                        instructions.AddRange(BitConverter.GetBytes(argument));

                        break;
                    }
                }
            }

            if (callDescriptor.Arguments.Length > 2)
            {
                var argument = callDescriptor.Arguments[2];

                switch (argument)
                {
                    case 0:
                    {
                        // xor r8d, r8d

                        instructions.AddRange(new byte[] {0x45, 0x31, 0xC0});

                        break;
                    }

                    case <= uint.MaxValue:
                    {
                        // mov r8d, argument

                        instructions.AddRange(new byte[] {0x41, 0xB8});

                        instructions.AddRange(BitConverter.GetBytes((int) argument));

                        break;
                    }

                    default:
                    {
                        // mov r8, argument

                        instructions.AddRange(new byte[] {0x49, 0xB8});

                        instructions.AddRange(BitConverter.GetBytes(argument));

                        break;
                    }
                }
            }

            if (callDescriptor.Arguments.Length > 3)
            {
                var argument = callDescriptor.Arguments[3];

                switch (argument)
                {
                    case 0:
                    {
                        // xor r9d, r9d

                        instructions.AddRange(new byte[] {0x45, 0x31, 0xC9});

                        break;
                    }

                    case <= uint.MaxValue:
                    {
                        // mov r9d, argument

                        instructions.AddRange(new byte[] {0x41, 0xB9});

                        instructions.AddRange(BitConverter.GetBytes((int) argument));

                        break;
                    }

                    default:
                    {
                        // mov r9, argument

                        instructions.AddRange(new byte[] {0x49, 0xB9});

                        instructions.AddRange(BitConverter.GetBytes(argument));

                        break;
                    }
                }
            }

            if (callDescriptor.Arguments.Length > 4)
            {
                foreach (var argument in callDescriptor.Arguments[4..].Reverse())
                {
                    switch (argument)
                    {
                        case <= sbyte.MaxValue:
                        {
                            // push argument

                            instructions.AddRange(new byte[] {0x6A, (byte) argument});

                            break;
                        }

                        case <= uint.MaxValue:
                        {
                            // push argument

                            instructions.Add(0x68);

                            instructions.AddRange(BitConverter.GetBytes((int) argument));

                            break;
                        }

                        default:
                        {
                            // mov rax, argument

                            instructions.AddRange(new byte[] {0x48, 0xB8});

                            instructions.AddRange(BitConverter.GetBytes(argument));

                            // push rax

                            instructions.Add(0x50);

                            break;
                        }
                    }
                }
            }

            // mov rax, Address

            instructions.AddRange(new byte[] {0x48, 0xB8});

            instructions.AddRange(BitConverter.GetBytes(callDescriptor.Address.ToInt64()));

            // call rax

            instructions.AddRange(new byte[] {0xFF, 0xD0});

            if (callDescriptor.ReturnAddress != IntPtr.Zero)
            {
                // mov ReturnAddress, rax

                instructions.AddRange(new byte[] {0x48, 0xA3});

                instructions.AddRange(BitConverter.GetBytes(callDescriptor.ReturnAddress.ToInt64()));
            }

            // xor eax, eax

            instructions.AddRange(new byte[] {0x31, 0xC0});

            // add rsp, 0x28

            instructions.AddRange(new byte[] {0x48, 0x83, 0xC4, 0x28});

            // ret

            instructions.Add(0xC3);

            return instructions.ToArray();
        }
    }
}