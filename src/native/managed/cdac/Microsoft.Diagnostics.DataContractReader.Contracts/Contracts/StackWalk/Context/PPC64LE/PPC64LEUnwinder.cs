// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using static Microsoft.Diagnostics.DataContractReader.Contracts.StackWalkHelpers.PPC64LEContext;

namespace Microsoft.Diagnostics.DataContractReader.Contracts.StackWalkHelpers.PPC64LE;

internal sealed class PPC64LEUnwinder(Target target)
{
    private const uint HeaderCodeWordsShift = 27;
    private const uint HeaderCodeWordsMask = 0x1f;
    private const uint HeaderEpilogCountShift = 22;
    private const uint HeaderEpilogCountMask = 0x1f;
    private const uint HeaderEBitShift = 21;
    private const uint HeaderEBitMask = 0x01;
    private const uint HeaderFunctionLengthMask = 0x3ffff;
    private const uint ExtendedCodeWordsShift = 16;
    private const uint ExtendedCodeWordsMask = 0xff;
    private const uint ExtendedEpilogCountMask = 0xffff;
    private const uint EpilogScopeStartMask = 0x3ffff;
    private const uint EpilogScopeIndexShift = 22;

    // PPC64LE unwind opcodes used by the JIT. The comments mirror the native
    // unwind encoder/dumper in src/coreclr/jit/unwindppc64le.cpp.
    private const byte AllocSmallMask = 0xe0; // alloc_s: 000xxxxx, sp -= x * 16
    private const byte AllocSmall = 0x00;
    private const byte AllocSmallValueMask = 0x1f;

    private const byte AllocMediumMask = 0xf8; // alloc_m: 11000xxx xxxxxxxx, sp -= x * 16
    private const byte AllocMedium = 0xc0;
    private const byte AllocMediumHighMask = 0x07;

    private const byte SaveReg = 0xd0; // save_reg: 11010000 rrrrrrrr zzzzzzzz, rN saved at [sp + z * 8]

    private const byte SaveFpRegMask = 0xfe; // save_freg: 1101110x xxxxzzzz zzzzzzzz, ignored by integer unwind
    private const byte SaveFpReg = 0xdc;

    private const byte AllocLarge = 0xe0; // alloc_l: 11100000 xxxxxxxx xxxxxxxx xxxxxxxx, sp -= x * 16
    private const byte SetFp = 0xe1;      // set_fp: 11100001, sp = fp
    private const byte AddFp = 0xe2;      // add_fp: 11100010 000xxxxx xxxxxxxx, sp = fp - x * 8
    private const byte EndMask = 0xfe;    // end/end_c: 1110010x
    private const byte End = 0xe4;
    private const byte SaveLr = 0xe6; // save_lr: 11100110 zzzzzzzz, lr saved at [sp + z * 8]

    private const uint StackAllocScale = 16;
    private const uint StackSlotSize = 8;
    private const uint SkipHalfWordsPerOpcode = 2;
    private const uint FirstNonvolatileGpr = 14;
    private const uint LastNonvolatileGpr = 31;

    private readonly Target _target = target;
    private readonly IExecutionManager _eman = target.Contracts.ExecutionManager;

    public bool Unwind(ref PPC64LEContext context)
    {
        if (_eman.GetCodeBlockHandle(context.InstructionPointer.Value) is not CodeBlockHandle cbh)
        {
            if (context.Link == 0)
            {
                return false;
            }

            context.Nip = context.Link;
            context.Link = 0;
            return true;
        }

        TargetPointer imageBase = _eman.GetUnwindInfoBaseAddress(cbh);
        Data.RuntimeFunction functionEntry = _target.ProcessedData.GetOrAdd<Data.RuntimeFunction>(_eman.GetUnwindInfo(cbh));

        ulong startingPc = context.Nip;
        ulong startingSp = context.R1;

        bool status = VirtualUnwind(ref context, imageBase, functionEntry);
        if (!status)
        {
            context.Nip = 0;
        }

        return context.Nip != 0 && (context.Nip != startingPc || context.R1 != startingSp);
    }

    private bool VirtualUnwind(ref PPC64LEContext context, TargetPointer imageBase, Data.RuntimeFunction functionEntry)
    {
        uint controlPcRva = (uint)(context.Nip - imageBase.Value);
        return VirtualUnwindFull(ref context, controlPcRva, imageBase, functionEntry);
    }

    private bool VirtualUnwindFull(ref PPC64LEContext context, uint controlPcRva, TargetPointer imageBase, Data.RuntimeFunction functionEntry)
    {
        context.ContextFlags |= (uint)ContextFlagsValues.CONTEXT_UNWOUND_TO_CALL;

        TargetPointer unwindData = imageBase.Value + functionEntry.UnwindData;
        uint header = _target.Read<uint>(unwindData);
        unwindData = unwindData.Value + sizeof(uint);

        uint codeWords = (header >> (int)HeaderCodeWordsShift) & HeaderCodeWordsMask;
        uint epilogCount = (header >> (int)HeaderEpilogCountShift) & HeaderEpilogCountMask;
        uint eBit = (header >> (int)HeaderEBitShift) & HeaderEBitMask;
        uint functionLength = header & HeaderFunctionLengthMask;
        uint offsetInFunction = (controlPcRva - functionEntry.BeginAddress) / 2;

        if ((codeWords == 0) && (epilogCount == 0))
        {
            uint extended = _target.Read<uint>(unwindData);
            unwindData = unwindData.Value + sizeof(uint);
            codeWords = (extended >> (int)ExtendedCodeWordsShift) & ExtendedCodeWordsMask;
            epilogCount = extended & ExtendedEpilogCountMask;
        }

        uint unwindIndex = 0;
        if (eBit != 0)
        {
            unwindIndex = epilogCount;
            epilogCount = 0;
        }

        TargetPointer epilogScopes = unwindData;
        TargetPointer code = unwindData.Value + (epilogCount * sizeof(uint));
        TargetPointer codeEnd = code.Value + (codeWords * sizeof(uint));

        uint skipHalfWords = 0;

        if (offsetInFunction < WordsToHalfWords(4 * codeWords))
        {
            uint scopeSize = WordsToHalfWords(ComputeScopeSize(code, codeEnd, isEpilog: false));
            if (offsetInFunction < scopeSize)
            {
                skipHalfWords = scopeSize - offsetInFunction;
            }
        }

        if (skipHalfWords == 0)
        {
            if (eBit != 0)
            {
                if (offsetInFunction + WordsToHalfWords(4 * codeWords - unwindIndex) >= functionLength)
                {
                    uint scopeSize = WordsToHalfWords(ComputeScopeSize(code.Value + unwindIndex, codeEnd, isEpilog: true));
                    uint scopeStart = functionLength - scopeSize;
                    if (offsetInFunction >= scopeStart)
                    {
                        code = code.Value + unwindIndex;
                        skipHalfWords = offsetInFunction - scopeStart;
                    }
                }
            }
            else
            {
                for (uint scope = 0; scope < epilogCount; scope++)
                {
                    uint epilogScope = _target.Read<uint>(epilogScopes.Value + (scope * sizeof(uint)));
                    uint scopeStart = epilogScope & EpilogScopeStartMask;
                    if (offsetInFunction < scopeStart)
                    {
                        break;
                    }

                    unwindIndex = epilogScope >> (int)EpilogScopeIndexShift;
                    if (offsetInFunction < scopeStart + WordsToHalfWords(4 * codeWords - unwindIndex))
                    {
                        uint scopeSize = WordsToHalfWords(ComputeScopeSize(code.Value + unwindIndex, codeEnd, isEpilog: true));
                        if (offsetInFunction < scopeStart + scopeSize)
                        {
                            code = code.Value + unwindIndex;
                            skipHalfWords = offsetInFunction - scopeStart;
                            break;
                        }
                    }
                }
            }
        }

        while (code < codeEnd && skipHalfWords > 0)
        {
            byte opcode = _target.Read<byte>(code);
            if (IsEndCode(opcode))
            {
                break;
            }

            code = code.Value + GetUnwindCodeSize(opcode);
            skipHalfWords = skipHalfWords > SkipHalfWordsPerOpcode ? skipHalfWords - SkipHalfWordsPerOpcode : 0;
        }

        try
        {
            while (code < codeEnd)
            {
                byte opcode = _target.Read<byte>(code);
                code = code.Value + 1;
                if (IsEndCode(opcode))
                {
                    break;
                }

                if ((opcode & AllocSmallMask) == AllocSmall)
                {
                    context.R1 += StackAllocScale * (uint)(opcode & AllocSmallValueMask);
                }
                else if ((opcode & AllocMediumMask) == AllocMedium)
                {
                    if (code >= codeEnd)
                    {
                        return false;
                    }

                    uint value = (uint)(((opcode & AllocMediumHighMask) << 8) | _target.Read<byte>(code));
                    code = code.Value + 1;
                    context.R1 += StackAllocScale * value;
                }
                else if (opcode == SaveReg)
                {
                    if (code.Value + 1 >= codeEnd.Value)
                    {
                        return false;
                    }

                    uint reg = _target.Read<byte>(code);
                    uint offset = (uint)_target.Read<byte>(code.Value + 1) * StackSlotSize;
                    code = code.Value + 2;
                    RestoreIntegerRegister(ref context, reg, context.R1 + offset);
                }
                else if ((opcode & SaveFpRegMask) == SaveFpReg)
                {
                    if (code.Value + 1 >= codeEnd.Value)
                    {
                        return false;
                    }

                    code = code.Value + 2;
                }
                else if (opcode == AllocLarge)
                {
                    if (code.Value + 2 >= codeEnd.Value)
                    {
                        return false;
                    }

                    uint value = (uint)((_target.Read<byte>(code) << 16) | (_target.Read<byte>(code.Value + 1) << 8) | _target.Read<byte>(code.Value + 2));
                    code = code.Value + 3;
                    context.R1 += StackAllocScale * value;
                }
                else if (opcode == SetFp)
                {
                    context.R1 = context.R31;
                }
                else if (opcode == AddFp)
                {
                    if (code.Value + 1 >= codeEnd.Value)
                    {
                        return false;
                    }

                    uint value = (uint)((_target.Read<byte>(code) << 8) | _target.Read<byte>(code.Value + 1));
                    code = code.Value + 2;
                    context.R1 = context.R31 - (StackSlotSize * value);
                }
                else if (opcode == SaveLr)
                {
                    if (code >= codeEnd)
                    {
                        return false;
                    }

                    uint offset = (uint)_target.Read<byte>(code) * StackSlotSize;
                    code = code.Value + 1;
                    context.Link = _target.Read<ulong>(context.R1 + offset);
                }
                else
                {
                    code = code.Value + GetUnwindCodeSize(opcode) - 1;
                }
            }
        }
        catch
        {
            return false;
        }

        context.Nip = context.Link;
        return true;
    }

    private uint ComputeScopeSize(TargetPointer code, TargetPointer codeEnd, bool isEpilog)
    {
        uint scopeSize = 0;
        while (code < codeEnd)
        {
            byte opcode = _target.Read<byte>(code);
            if (IsEndCode(opcode))
            {
                break;
            }

            code = code.Value + GetUnwindCodeSize(opcode);
            scopeSize++;
        }

        return isEpilog ? scopeSize + 1 : scopeSize;
    }

    private static bool IsEndCode(byte opcode)
    {
        return (opcode & EndMask) == End;
    }

    private static uint WordsToHalfWords(uint value)
    {
        return value << 1;
    }

    private static uint GetUnwindCodeSize(byte opcode)
    {
        if ((opcode & AllocSmallMask) == AllocSmall)
        {
            return 1;
        }

        if ((opcode & AllocMediumMask) == AllocMedium)
        {
            return 2;
        }

        if ((opcode == SaveReg) || ((opcode & SaveFpRegMask) == SaveFpReg) || (opcode == AddFp))
        {
            return 3;
        }

        if (opcode == AllocLarge)
        {
            return 4;
        }

        if (opcode == SaveLr)
        {
            return 2;
        }

        return 1;
    }

    private void RestoreIntegerRegister(ref PPC64LEContext context, uint reg, ulong address)
    {
        if (reg < FirstNonvolatileGpr || reg > LastNonvolatileGpr)
        {
            return;
        }

        context.TrySetRegister((int)reg, new TargetNUInt(_target.Read<ulong>(address)));
    }
}
