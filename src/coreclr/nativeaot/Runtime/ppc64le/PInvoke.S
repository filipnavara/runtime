// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "AsmMacros_Shared.h"

.abiversion 2
.text

.globl RhpTrapThreads

.macro DEFINE_FUNC name
    .p2align 2
    .globl \name
    .type \name,@function
\name:
.endm

.macro END_FUNC name
    .size \name, .-\name
.endm

// r3: address of PInvokeTransitionFrame
DEFINE_FUNC RhpPInvoke
    mflr 0
    mr 12, 1
    stdu 1, -256(1)
    std 0, 128(1)
    std 14, 136(1)
    std 3, 144(1)

    mr 14, 3
    std 31, 0(14)       // PInvokeTransitionFrame::m_FramePointer
    std 0, 8(14)        // PInvokeTransitionFrame::m_RIP
    std 12, 32(14)      // PInvokeTransitionFrame::m_PreservedRegs[0]
    lis 12, 0x2         // PTFF_SAVE_SP
    std 12, 24(14)      // PInvokeTransitionFrame::m_Flags

    INLINE_GETTHREAD 11

    ld 14, 144(1)
    std 11, 16(14)      // PInvokeTransitionFrame::m_pThread
    std 14, 72(11)      // Thread::m_pTransitionFrame

    ld 14, 136(1)
    ld 0, 128(1)
    mtlr 0
    addi 1, 1, 256
    blr
END_FUNC RhpPInvoke

// r3: address of PInvokeTransitionFrame
DEFINE_FUNC RhpPInvokeReturn
    ld 11, 16(3)
    li 12, 0
    std 12, 72(11)      // Thread::m_pTransitionFrame

    addis 12, 2, RhpTrapThreads@toc@ha
    lwz 12, RhpTrapThreads@toc@l(12)
    cmpwi 12, 0
    bne 1f
    blr

1:
    b RhpWaitForGC2
END_FUNC RhpPInvokeReturn
