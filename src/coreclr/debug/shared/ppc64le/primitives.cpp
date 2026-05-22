// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//*****************************************************************************
// File: primitives.cpp
//

//
// Platform-specific debugger primitives
//
//*****************************************************************************

#include "primitives.h"

void CORDbgCopyThreadContext(DT_CONTEXT* pDst, const DT_CONTEXT* pSrc)
{
    DWORD dstFlags = pDst->ContextFlags;
    DWORD srcFlags = pSrc->ContextFlags;

    if ((dstFlags & srcFlags & DT_CONTEXT_CONTROL) == DT_CONTEXT_CONTROL)
    {
        pDst->Nip = pSrc->Nip;
        pDst->R1 = pSrc->R1;
        pDst->R31 = pSrc->R31;
        pDst->Link = pSrc->Link;
        pDst->Ctr = pSrc->Ctr;
        pDst->Msr = pSrc->Msr;
    }

    if ((dstFlags & srcFlags & DT_CONTEXT_INTEGER) == DT_CONTEXT_INTEGER)
    {
        CopyContextChunk(&pDst->R0, &pSrc->R0, &pDst->R31, DT_CONTEXT_INTEGER);
    }

    if ((dstFlags & srcFlags & DT_CONTEXT_FLOATING_POINT) == DT_CONTEXT_FLOATING_POINT)
    {
        CopyContextChunk(&pDst->F0, &pSrc->F0, &pDst->F31, DT_CONTEXT_FLOATING_POINT);
        pDst->Fpscr = pSrc->Fpscr;
    }
}

#if defined(ALLOW_VMPTR_ACCESS) || !defined(RIGHT_SIDE_COMPILE)
void SetDebuggerREGDISPLAYFromREGDISPLAY(DebuggerREGDISPLAY* pDRD, REGDISPLAY* pRD)
{
    SUPPORTS_DAC_HOST_ONLY;

    DT_CONTEXT* pContext = reinterpret_cast<DT_CONTEXT*>(pRD->pCurrentContext);
    DWORD flags = pContext->ContextFlags;

    if ((flags & DT_CONTEXT_CONTROL) == DT_CONTEXT_CONTROL)
    {
        pDRD->FP = (SIZE_T)CORDbgGetFP(pContext);
        pDRD->PC = (SIZE_T)pContext->Nip;
    }

    if ((flags & DT_CONTEXT_INTEGER) == DT_CONTEXT_INTEGER)
    {
        memcpy(pDRD->R, &pContext->R0, sizeof(pDRD->R));
    }

    pDRD->SP = pRD->SP;
}
#endif // ALLOW_VMPTR_ACCESS || !RIGHT_SIDE_COMPILE

