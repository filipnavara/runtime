// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include <ppc64le/InlineTls.inc>

// Inlined version of RhpGetThread.
.macro INLINE_GETTHREAD target
    INLINE_GET_TLS_VAR \target, C_FUNC(tls_CurrentThread)
.endm

.macro INLINE_GET_ALLOC_CONTEXT_BASE target
    INLINE_GETTHREAD \target
.endm

.macro NESTED_ENTRY Name, Section, Handler
    LEAF_ENTRY \Name, \Section
    .ifnc \Handler, NoHandler
    .personality C_FUNC(\Handler)
    .endif
.endm

.macro NESTED_END Name, Section
    LEAF_END \Name, \Section
.endm

.macro LEAF_ENTRY Name, Section
    .global C_FUNC(\Name)
    .type \Name, %function
C_FUNC(\Name):
    .cfi_startproc
.endm

.macro LEAF_END Name, Section
    .size \Name, .-\Name
    .cfi_endproc
.endm

.macro PUSH_COOP_PINVOKE_FRAME target
    mflr 0
    stdu 1, -304(1)
    std 2, 24(1)
    std 31, 128(1)      // PInvokeTransitionFrame::m_FramePointer
    std 0, 136(1)       // PInvokeTransitionFrame::m_RIP
    li 12, 0
    std 12, 144(1)      // PInvokeTransitionFrame::m_pThread
    lis 12, 0x3
    ori 12, 12, 0xffff  // PTFF_SAVE_R14..R30 | PTFF_SAVE_SP
    std 12, 152(1)      // PInvokeTransitionFrame::m_Flags
    std 14, 160(1)
    std 15, 168(1)
    std 16, 176(1)
    std 17, 184(1)
    std 18, 192(1)
    std 19, 200(1)
    std 20, 208(1)
    std 21, 216(1)
    std 22, 224(1)
    std 23, 232(1)
    std 24, 240(1)
    std 25, 248(1)
    std 26, 256(1)
    std 27, 264(1)
    std 28, 272(1)
    std 29, 280(1)
    std 30, 288(1)
    addi 12, 1, 304
    std 12, 296(1)
    addi \target, 1, 128
.endm

.macro POP_COOP_PINVOKE_FRAME
    ld 14, 160(1)
    ld 15, 168(1)
    ld 16, 176(1)
    ld 17, 184(1)
    ld 18, 192(1)
    ld 19, 200(1)
    ld 20, 208(1)
    ld 21, 216(1)
    ld 22, 224(1)
    ld 23, 232(1)
    ld 24, 240(1)
    ld 25, 248(1)
    ld 26, 256(1)
    ld 27, 264(1)
    ld 28, 272(1)
    ld 29, 280(1)
    ld 30, 288(1)
    ld 2, 24(1)
    ld 0, 136(1)
    mtlr 0
    addi 1, 1, 304
.endm

.macro EPILOG_RETURN
    blr
.endm
