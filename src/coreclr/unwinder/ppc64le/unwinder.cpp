// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "stdafx.h"
#include "utilcode.h"
#include "crosscomp.h"

#include "unwinder.h"

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
    if (ARGUMENT_PRESENT(EstablisherFrame))
    {
        *EstablisherFrame = ContextRecord->R1;
    }

    if (ARGUMENT_PRESENT(HandlerData))
    {
        *HandlerData = nullptr;
    }

    if (ARGUMENT_PRESENT(ContextPointers))
    {
        ContextPointers->R14 = &ContextRecord->R14;
        ContextPointers->R15 = &ContextRecord->R15;
        ContextPointers->R16 = &ContextRecord->R16;
        ContextPointers->R17 = &ContextRecord->R17;
        ContextPointers->R18 = &ContextRecord->R18;
        ContextPointers->R19 = &ContextRecord->R19;
        ContextPointers->R20 = &ContextRecord->R20;
        ContextPointers->R21 = &ContextRecord->R21;
        ContextPointers->R22 = &ContextRecord->R22;
        ContextPointers->R23 = &ContextRecord->R23;
        ContextPointers->R24 = &ContextRecord->R24;
        ContextPointers->R25 = &ContextRecord->R25;
        ContextPointers->R26 = &ContextRecord->R26;
        ContextPointers->R27 = &ContextRecord->R27;
        ContextPointers->R28 = &ContextRecord->R28;
        ContextPointers->R29 = &ContextRecord->R29;
        ContextPointers->R30 = &ContextRecord->R30;
        ContextPointers->R31 = &ContextRecord->R31;
    }

    if (ContextRecord->Link != 0)
    {
        ContextRecord->Nip = ContextRecord->Link;
        ContextRecord->Link = 0;
    }
    else
    {
        ContextRecord->Nip = 0;
    }

    return nullptr;
}
#endif // HOST_UNIX
