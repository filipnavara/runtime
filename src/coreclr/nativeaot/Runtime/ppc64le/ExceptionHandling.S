// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "AsmOffsets.inc"

.abiversion 2
.text

#define STACKSIZEOF_ExInfo      ((SIZEOF__ExInfo + 15) & ~15)
#define STACKSIZEOF_Context     ((SIZEOF__PAL_LIMITED_CONTEXT + 15) & ~15)
#define THROW_ABI_FRAME_HEADER  0x40
#define THROW_FRAME_SIZE        (THROW_ABI_FRAME_HEADER + STACKSIZEOF_ExInfo + STACKSIZEOF_Context)

#define TSF_DoNotTriggerGc      0x10

#define ExKind_Throw            1
#define ExKind_HardwareFault    2
#define ExKind_RethrowFlag      4

#define rsp_offsetof_ExInfo     THROW_ABI_FRAME_HEADER
#define rsp_offsetof_Context    (THROW_ABI_FRAME_HEADER + STACKSIZEOF_ExInfo)

#define OFFSETOF__PAL_LIMITED_CONTEXT__F14 0xB8

#define CATCH_ABI_FRAME_HEADER  0x40
#define CATCH_FRAME_SIZE        0x100
#define CATCH_OFFSET_EXCEPTION  CATCH_ABI_FRAME_HEADER
#define CATCH_OFFSET_HANDLER    (CATCH_OFFSET_EXCEPTION + 0x08)
#define CATCH_OFFSET_REGDISPLAY (CATCH_OFFSET_HANDLER + 0x08)
#define CATCH_OFFSET_EXINFO     (CATCH_OFFSET_REGDISPLAY + 0x08)
#define CATCH_OFFSET_THREAD     (CATCH_OFFSET_EXINFO + 0x08)
#define CATCH_OFFSET_FP         (CATCH_OFFSET_THREAD + 0x08)
#define CATCH_OFFSET_LR         (CATCH_OFFSET_FP + 0x08)
#define CATCH_OFFSET_R14        (CATCH_OFFSET_LR + 0x08)

.globl RhpTrapThreads

.macro DEFINE_FUNC name
    .p2align 2
    .globl \name
    .type \name,@function
\name:
    .cfi_startproc
.endm

.macro DEFINE_LABEL name
    .globl \name
    .type \name,@function
\name:
.endm

.macro END_FUNC name
    .cfi_endproc
    .size \name, .-\name
.endm

.macro DEFINE_TRAP_HELPER name
DEFINE_FUNC \name
    trap
    blr
END_FUNC \name
.endm

.macro STORE_PAL_CONTEXT software
    mflr 8
    .if \software
        mr 0, 8
    .endif

    mr 12, 1
    stdu 1, -THROW_FRAME_SIZE(1)
    std 8, 16(1)
    .cfi_def_cfa 1, THROW_FRAME_SIZE
    .cfi_offset 65, 16 - THROW_FRAME_SIZE
    addi 9, 1, rsp_offsetof_Context

    std 31, OFFSETOF__PAL_LIMITED_CONTEXT__FP(9)
    std 0,  OFFSETOF__PAL_LIMITED_CONTEXT__LR(9)
    std 3,  OFFSETOF__PAL_LIMITED_CONTEXT__R3(9)
    std 4,  OFFSETOF__PAL_LIMITED_CONTEXT__R4(9)
    std 14, OFFSETOF__PAL_LIMITED_CONTEXT__R14(9)
    std 15, OFFSETOF__PAL_LIMITED_CONTEXT__R15(9)
    std 16, OFFSETOF__PAL_LIMITED_CONTEXT__R16(9)
    std 17, OFFSETOF__PAL_LIMITED_CONTEXT__R17(9)
    std 18, OFFSETOF__PAL_LIMITED_CONTEXT__R18(9)
    std 19, OFFSETOF__PAL_LIMITED_CONTEXT__R19(9)
    std 20, OFFSETOF__PAL_LIMITED_CONTEXT__R20(9)
    std 21, OFFSETOF__PAL_LIMITED_CONTEXT__R21(9)
    std 22, OFFSETOF__PAL_LIMITED_CONTEXT__R22(9)
    std 23, OFFSETOF__PAL_LIMITED_CONTEXT__R23(9)
    std 24, OFFSETOF__PAL_LIMITED_CONTEXT__R24(9)
    std 25, OFFSETOF__PAL_LIMITED_CONTEXT__R25(9)
    std 26, OFFSETOF__PAL_LIMITED_CONTEXT__R26(9)
    std 27, OFFSETOF__PAL_LIMITED_CONTEXT__R27(9)
    std 28, OFFSETOF__PAL_LIMITED_CONTEXT__R28(9)
    std 29, OFFSETOF__PAL_LIMITED_CONTEXT__R29(9)
    std 30, OFFSETOF__PAL_LIMITED_CONTEXT__R30(9)
    std 12, OFFSETOF__PAL_LIMITED_CONTEXT__SP(9)
    std 0,  OFFSETOF__PAL_LIMITED_CONTEXT__IP(9)

    stfd 14, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x00(9)
    stfd 15, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x08(9)
    stfd 16, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x10(9)
    stfd 17, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x18(9)
    stfd 18, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x20(9)
    stfd 19, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x28(9)
    stfd 20, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x30(9)
    stfd 21, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x38(9)
    stfd 22, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x40(9)
    stfd 23, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x48(9)
    stfd 24, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x50(9)
    stfd 25, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x58(9)
    stfd 26, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x60(9)
    stfd 27, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x68(9)
    stfd 28, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x70(9)
    stfd 29, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x78(9)
    stfd 30, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x80(9)
    stfd 31, OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x88(9)
.endm

.macro INIT_EXINFO exInfoReg, contextReg, kindReg
    li 10, 0
    std 10, OFFSETOF__ExInfo__m_exception(\exInfoReg)
    li 10, 1
    stb 10, OFFSETOF__ExInfo__m_passNumber(\exInfoReg)
    li 10, -1
    stw 10, OFFSETOF__ExInfo__m_idxCurClause(\exInfoReg)
    stb \kindReg, OFFSETOF__ExInfo__m_kind(\exInfoReg)
    std \contextReg, OFFSETOF__ExInfo__m_pExContext(\exInfoReg)
.endm

.macro LINK_EXINFO threadReg, exInfoReg
    ld 10, OFFSETOF__Thread__m_pExInfoStackHead(\threadReg)
    std 10, OFFSETOF__ExInfo__m_pPrevExInfo(\exInfoReg)
    std \exInfoReg, OFFSETOF__Thread__m_pExInfoStackHead(\threadReg)
.endm

.macro RESTORE_PRESERVED_REGISTERS regDisplayReg
    ld 12, OFFSETOF__REGDISPLAY__pR14(\regDisplayReg)
    ld 14, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR15(\regDisplayReg)
    ld 15, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR16(\regDisplayReg)
    ld 16, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR17(\regDisplayReg)
    ld 17, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR18(\regDisplayReg)
    ld 18, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR19(\regDisplayReg)
    ld 19, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR20(\regDisplayReg)
    ld 20, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR21(\regDisplayReg)
    ld 21, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR22(\regDisplayReg)
    ld 22, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR23(\regDisplayReg)
    ld 23, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR24(\regDisplayReg)
    ld 24, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR25(\regDisplayReg)
    ld 25, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR26(\regDisplayReg)
    ld 26, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR27(\regDisplayReg)
    ld 27, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR28(\regDisplayReg)
    ld 28, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR29(\regDisplayReg)
    ld 29, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR30(\regDisplayReg)
    ld 30, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pFP(\regDisplayReg)
    ld 31, 0(12)
.endm

.macro SAVE_CATCH_FRAME_GPRS
    std 31, CATCH_OFFSET_FP(1)
    std 0,  CATCH_OFFSET_LR(1)
    std 14, CATCH_OFFSET_R14 + 0x00(1)
    std 15, CATCH_OFFSET_R14 + 0x08(1)
    std 16, CATCH_OFFSET_R14 + 0x10(1)
    std 17, CATCH_OFFSET_R14 + 0x18(1)
    std 18, CATCH_OFFSET_R14 + 0x20(1)
    std 19, CATCH_OFFSET_R14 + 0x28(1)
    std 20, CATCH_OFFSET_R14 + 0x30(1)
    std 21, CATCH_OFFSET_R14 + 0x38(1)
    std 22, CATCH_OFFSET_R14 + 0x40(1)
    std 23, CATCH_OFFSET_R14 + 0x48(1)
    std 24, CATCH_OFFSET_R14 + 0x50(1)
    std 25, CATCH_OFFSET_R14 + 0x58(1)
    std 26, CATCH_OFFSET_R14 + 0x60(1)
    std 27, CATCH_OFFSET_R14 + 0x68(1)
    std 28, CATCH_OFFSET_R14 + 0x70(1)
    std 29, CATCH_OFFSET_R14 + 0x78(1)
    std 30, CATCH_OFFSET_R14 + 0x80(1)
.endm

.macro INLINE_THREAD_UNHIJACK_PPC64 threadReg
    ld 10, OFFSETOF__Thread__m_pvHijackedReturnAddress(\threadReg)
    cmpdi 10, 0
    beq 9f
    ld 11, OFFSETOF__Thread__m_ppvHijackedReturnAddressLocation(\threadReg)
    std 10, 0(11)
    li 12, 0
    std 12, OFFSETOF__Thread__m_ppvHijackedReturnAddressLocation(\threadReg)
    std 12, OFFSETOF__Thread__m_pvHijackedReturnAddress(\threadReg)
9:
.endm

//
// void RhpThrowHwEx(uintptr_t exceptionCode, uintptr_t faultingIP)
//
DEFINE_FUNC RhpThrowHwEx
    mr 0, 4
    STORE_PAL_CONTEXT 0

    addi 14, 1, rsp_offsetof_ExInfo
    addi 15, 1, rsp_offsetof_Context
    li 16, ExKind_HardwareFault
    INIT_EXINFO 14, 15, 16

    bl RhpGetThread
    nop

    LINK_EXINFO 3, 14

    ld 3, OFFSETOF__PAL_LIMITED_CONTEXT__R3(15)
    mr 4, 14
    bl RhThrowHwEx
    nop
DEFINE_LABEL RhpThrowHwEx2
    trap
END_FUNC RhpThrowHwEx

//
// void RhpThrowExact(object exceptionObj)
//
DEFINE_FUNC RhpThrowExact
    li 11, ExKind_RethrowFlag
    b RhpThrowImpl
END_FUNC RhpThrowExact

//
// void RhpThrowEx(object exceptionObj)
//
DEFINE_FUNC RhpThrowEx
    li 11, ExKind_Throw
    b RhpThrowImpl
END_FUNC RhpThrowEx

DEFINE_FUNC RhpThrowImpl
    STORE_PAL_CONTEXT 1

    addi 14, 1, rsp_offsetof_ExInfo
    addi 15, 1, rsp_offsetof_Context
    INIT_EXINFO 14, 15, 11

    bl RhpGetThread
    nop
    mr 16, 3

    ld 10, OFFSETOF__Thread__m_pvHijackedReturnAddress(16)
    cmpdi 10, 0
    beq 1f

    ld 11, OFFSETOF__Thread__m_ppvHijackedReturnAddressLocation(16)

    addi 12, 1, THROW_FRAME_SIZE
    cmpld 11, 12
    blt 2f

    std 10, 0(11)
    b 3f

2:
    std 10, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__LR(1)
    std 10, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__IP(1)

3:
    li 12, 0
    std 12, OFFSETOF__Thread__m_ppvHijackedReturnAddressLocation(16)
    std 12, OFFSETOF__Thread__m_pvHijackedReturnAddress(16)

1:
    LINK_EXINFO 16, 14

    ld 3, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R3(1)
    mr 4, 14
    bl RhThrowEx
    nop

DEFINE_LABEL RhpThrowImpl2
    trap
END_FUNC RhpThrowImpl

DEFINE_TRAP_HELPER RhpRethrow
DEFINE_TRAP_HELPER RhpRethrow2

//
// void* RhpCallCatchFunclet(object exceptionObj, void* pHandlerIP, REGDISPLAY* pRegDisplay, ExInfo* pExInfo)
//
DEFINE_FUNC RhpCallCatchFunclet
    mflr 0
    stdu 1, -CATCH_FRAME_SIZE(1)
    .cfi_def_cfa 1, CATCH_FRAME_SIZE
    .cfi_offset 65, CATCH_OFFSET_LR - CATCH_FRAME_SIZE
    .cfi_offset 31, CATCH_OFFSET_FP - CATCH_FRAME_SIZE
    std 3, CATCH_OFFSET_EXCEPTION(1)
    std 4, CATCH_OFFSET_HANDLER(1)
    std 5, CATCH_OFFSET_REGDISPLAY(1)
    std 6, CATCH_OFFSET_EXINFO(1)
    SAVE_CATCH_FRAME_GPRS

    bl RhpGetThread
    nop
    std 3, CATCH_OFFSET_THREAD(1)

    lwz 10, OFFSETOF__Thread__m_ThreadStateFlags(3)
    li 11, -17
    and 10, 10, 11
    stw 10, OFFSETOF__Thread__m_ThreadStateFlags(3)

    ld 3, CATCH_OFFSET_EXCEPTION(1)
    ld 4, CATCH_OFFSET_HANDLER(1)
    ld 5, CATCH_OFFSET_REGDISPLAY(1)

    RESTORE_PRESERVED_REGISTERS 5

    mtctr 4
    bctrl

DEFINE_LABEL RhpCallCatchFunclet2
    // r3 contains the resume IP returned by the catch funclet.
    ld 5, CATCH_OFFSET_REGDISPLAY(1)
    ld 6, CATCH_OFFSET_EXINFO(1)
    ld 7, CATCH_OFFSET_THREAD(1)

    INLINE_THREAD_UNHIJACK_PPC64 7

    ld 4, OFFSETOF__REGDISPLAY__SP(5)

4:
    ld 6, OFFSETOF__ExInfo__m_pPrevExInfo(6)
    cmpdi 6, 0
    beq 5f
    cmpld 6, 4
    blt 4b

5:
    std 6, OFFSETOF__Thread__m_pExInfoStackHead(7)

    mr 1, 4
    mtctr 3
    bctr
END_FUNC RhpCallCatchFunclet

DEFINE_TRAP_HELPER RhpCallFinallyFunclet
DEFINE_TRAP_HELPER RhpCallFinallyFunclet2
DEFINE_TRAP_HELPER RhpCallFilterFunclet
DEFINE_TRAP_HELPER RhpCallFilterFunclet2
DEFINE_TRAP_HELPER RhpCallPropagateExceptionCallback
