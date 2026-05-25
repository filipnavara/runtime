// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "stdafx.h"
#include "utilcode.h"
#include "crosscomp.h"

#include "unwinder.h"

static bool IsEndCode(BYTE opcode)
{
    return (opcode & 0xFE) == 0xE4;
}

static BYTE ReadUnwindByte(ULONG_PTR address)
{
    return *dac_cast<PTR_BYTE>(address);
}

static DWORD ReadUnwindDword(ULONG_PTR address)
{
    return *dac_cast<PTR_DWORD>(address);
}

static DWORD64 ReadStackQword(DWORD64 address)
{
    return *dac_cast<PTR_UINT64>(address);
}

static void RestoreIntegerRegister(PCONTEXT context, PT_KNONVOLATILE_CONTEXT_POINTERS contextPointers, DWORD reg, DWORD64 address)
{
    DWORD64 value = ReadStackQword(address);

    switch (reg)
    {
        case 14:
            context->R14 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R14 = (PDWORD64)address;
            }
            break;
        case 15:
            context->R15 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R15 = (PDWORD64)address;
            }
            break;
        case 16:
            context->R16 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R16 = (PDWORD64)address;
            }
            break;
        case 17:
            context->R17 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R17 = (PDWORD64)address;
            }
            break;
        case 18:
            context->R18 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R18 = (PDWORD64)address;
            }
            break;
        case 19:
            context->R19 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R19 = (PDWORD64)address;
            }
            break;
        case 20:
            context->R20 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R20 = (PDWORD64)address;
            }
            break;
        case 21:
            context->R21 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R21 = (PDWORD64)address;
            }
            break;
        case 22:
            context->R22 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R22 = (PDWORD64)address;
            }
            break;
        case 23:
            context->R23 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R23 = (PDWORD64)address;
            }
            break;
        case 24:
            context->R24 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R24 = (PDWORD64)address;
            }
            break;
        case 25:
            context->R25 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R25 = (PDWORD64)address;
            }
            break;
        case 26:
            context->R26 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R26 = (PDWORD64)address;
            }
            break;
        case 27:
            context->R27 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R27 = (PDWORD64)address;
            }
            break;
        case 28:
            context->R28 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R28 = (PDWORD64)address;
            }
            break;
        case 29:
            context->R29 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R29 = (PDWORD64)address;
            }
            break;
        case 30:
            context->R30 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R30 = (PDWORD64)address;
            }
            break;
        case 31:
            context->R31 = value;
            if (contextPointers != nullptr)
            {
                contextPointers->R31 = (PDWORD64)address;
            }
            break;
        default:
            break;
    }
}

static unsigned GetUnwindCodeSize(BYTE opcode)
{
    if ((opcode & 0xE0) == 0x00)
    {
        return 1;
    }

    if ((opcode & 0xF8) == 0xC0)
    {
        return 2;
    }

    if ((opcode == 0xD0) || ((opcode & 0xFE) == 0xDC) || (opcode == 0xE2))
    {
        return 3;
    }

    if (opcode == 0xE0)
    {
        return 4;
    }

    if (opcode == 0xE6)
    {
        return 2;
    }

    return 1;
}

static void UnwindPpc64leJitFrame(
    ULONG64 imageBase,
    PCONTEXT context,
    PT_RUNTIME_FUNCTION functionEntry,
    PULONG64 establisherFrame,
    PT_KNONVOLATILE_CONTEXT_POINTERS contextPointers)
{
    ULONG_PTR unwindData = imageBase + functionEntry->UnwindData;
    DWORD     header     = ReadUnwindDword(unwindData);
    unwindData += sizeof(DWORD);

    DWORD codeWords   = (header >> 27) & 0x1F;
    DWORD epilogCount = (header >> 22) & 0x1F;
    DWORD eBit        = (header >> 21) & 0x01;

    if ((codeWords == 0) && (epilogCount == 0))
    {
        DWORD extended = ReadUnwindDword(unwindData);
        unwindData += sizeof(DWORD);
        codeWords   = (extended >> 16) & 0xFF;
        epilogCount = extended & 0xFFFF;
    }

    if (eBit == 0)
    {
        unwindData += epilogCount * sizeof(DWORD);
    }

    ULONG_PTR code    = unwindData;
    ULONG_PTR codeEnd = unwindData + (codeWords * sizeof(DWORD));

    DWORD savedIntegerCalleeCount = 0;
    bool  restoredLink            = false;

    while (code < codeEnd)
    {
        BYTE opcode = ReadUnwindByte(code++);
        if (IsEndCode(opcode))
        {
            break;
        }

        if ((opcode & 0xE0) == 0x00)
        {
            context->R1 += 16 * (opcode & 0x1F);
        }
        else if ((opcode & 0xF8) == 0xC0)
        {
            DWORD value = ((opcode & 0x07) << 8) | ReadUnwindByte(code);
            code += 1;
            context->R1 += 16 * value;
        }
        else if (opcode == 0xD0)
        {
            DWORD reg    = ReadUnwindByte(code);
            DWORD offset = ReadUnwindByte(code + 1) * sizeof(DWORD64);
            code += 2;

            RestoreIntegerRegister(context, contextPointers, reg, context->R1 + offset);

            if ((reg >= 14) && (reg <= 30))
            {
                savedIntegerCalleeCount++;
            }
        }
        else if ((opcode & 0xFE) == 0xDC)
        {
            code += 2;
        }
        else if (opcode == 0xE0)
        {
            DWORD value = (ReadUnwindByte(code) << 16) | (ReadUnwindByte(code + 1) << 8) | ReadUnwindByte(code + 2);
            code += 3;
            context->R1 += 16 * value;
        }
        else if (opcode == 0xE1)
        {
            context->R1 = context->R31;
        }
        else if (opcode == 0xE2)
        {
            DWORD value = (ReadUnwindByte(code) << 8) | ReadUnwindByte(code + 1);
            code += 2;
            context->R1 = context->R31 - (8 * value);
        }
        else if (opcode == 0xE6)
        {
            DWORD offset  = ReadUnwindByte(code) * sizeof(DWORD64);
            code += 1;

            context->Link = ReadStackQword(context->R1 + offset);
            restoredLink  = true;
        }
        else
        {
            code += GetUnwindCodeSize(opcode) - 1;
        }
    }

    if (!restoredLink)
    {
        DWORD64 linkAddress = context->R1 - ((savedIntegerCalleeCount + 1) * sizeof(DWORD64));
        context->Link       = ReadStackQword(linkAddress);
    }

    context->Nip = context->Link;

    if (establisherFrame != nullptr)
    {
        *establisherFrame = context->R1;
    }
}

BOOL OOPStackUnwinderPPC64LE::Unwind(T_CONTEXT* pContext)
{
    if (pContext->Link == 0)
    {
        return FALSE;
    }

    pContext->Nip = pContext->Link;
    pContext->Link = 0;
    return TRUE;
}

BOOL DacUnwindStackFrame(T_CONTEXT* pContext, T_KNONVOLATILE_CONTEXT_POINTERS* pContextPointers)
{
    OOPStackUnwinderPPC64LE unwinder;
    BOOL res = unwinder.Unwind(pContext);

    if (res && (pContextPointers != nullptr))
    {
        pContextPointers->R14 = &pContext->R14;
        pContextPointers->R15 = &pContext->R15;
        pContextPointers->R16 = &pContext->R16;
        pContextPointers->R17 = &pContext->R17;
        pContextPointers->R18 = &pContext->R18;
        pContextPointers->R19 = &pContext->R19;
        pContextPointers->R20 = &pContext->R20;
        pContextPointers->R21 = &pContext->R21;
        pContextPointers->R22 = &pContext->R22;
        pContextPointers->R23 = &pContext->R23;
        pContextPointers->R24 = &pContext->R24;
        pContextPointers->R25 = &pContext->R25;
        pContextPointers->R26 = &pContext->R26;
        pContextPointers->R27 = &pContext->R27;
        pContextPointers->R28 = &pContext->R28;
        pContextPointers->R29 = &pContext->R29;
        pContextPointers->R30 = &pContext->R30;
        pContextPointers->R31 = &pContext->R31;
    }

    return res;
}

#if defined(HOST_UNIX)
PEXCEPTION_ROUTINE
RtlVirtualUnwind(
    IN ULONG HandlerType,
    IN ULONG64 ImageBase,
    IN ULONG64 ControlPc,
    IN PT_RUNTIME_FUNCTION FunctionEntry,
    IN OUT PCONTEXT ContextRecord,
    OUT PVOID* HandlerData,
    OUT PULONG64 EstablisherFrame,
    IN OUT PT_KNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL)
{
    ContextRecord->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;

    if (ARGUMENT_PRESENT(EstablisherFrame))
    {
        *EstablisherFrame = ContextRecord->R1;
    }

    if (ARGUMENT_PRESENT(HandlerData))
    {
        *HandlerData = nullptr;
    }

    if (FunctionEntry != nullptr)
    {
        UnwindPpc64leJitFrame(ImageBase, ContextRecord, FunctionEntry, EstablisherFrame, ContextPointers);
    }
    else
    {
        ContextRecord->Nip = ContextRecord->Link;
    }

    return nullptr;
}
#endif // HOST_UNIX
