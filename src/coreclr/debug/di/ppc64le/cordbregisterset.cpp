// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "primitives.h"

HRESULT CordbRegisterSet::GetRegistersAvailable(ULONG64* pAvailable)
{
    FAIL_IF_NEUTERED(this);
    VALIDATE_POINTER_TO_OBJECT(pAvailable, ULONG64*);

    *pAvailable = SETBITULONG64(REGISTER_INSTRUCTION_POINTER) |
                  SETBITULONG64(REGISTER_STACK_POINTER) |
                  SETBITULONG64(REGISTER_FRAME_POINTER);

    return S_OK;
}

HRESULT CordbRegisterSet::GetRegisters(ULONG64 mask, ULONG32 regCount, CORDB_REGISTER regBuffer[])
{
    _ASSERTE(!"PPC64LE:NYI");
    return S_OK;
}

HRESULT CordbRegisterSet::GetRegistersAvailable(ULONG32 regCount, BYTE pAvailable[])
{
    _ASSERTE(!"PPC64LE:NYI");
    return S_OK;
}

HRESULT CordbRegisterSet::GetRegisters(ULONG32 maskCount, BYTE mask[], ULONG32 regCount, CORDB_REGISTER regBuffer[])
{
    _ASSERTE(!"PPC64LE:NYI");
    return S_OK;
}

void CordbRegisterSet::InternalCopyRDToContext(DT_CONTEXT* pInputContext)
{
    _ASSERTE(!"PPC64LE:NYI");
}
