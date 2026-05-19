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

#define OFFSETOF__PAL_LIMITED_CONTEXT__F14 0xF8

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

#define FUNCLET_FRAME_SIZE      0x190
#define FUNCLET_OFFSET_HANDLER  0x40
#define FUNCLET_OFFSET_REGDISPLAY (FUNCLET_OFFSET_HANDLER + 0x08)
#define FUNCLET_OFFSET_THREAD   (FUNCLET_OFFSET_REGDISPLAY + 0x08)
#define FUNCLET_OFFSET_FP       (FUNCLET_OFFSET_THREAD + 0x08)
#define FUNCLET_OFFSET_LR       (FUNCLET_OFFSET_FP + 0x08)
#define FUNCLET_OFFSET_R14      (FUNCLET_OFFSET_LR + 0x08)
#define FUNCLET_OFFSET_F14      (FUNCLET_OFFSET_R14 + 0x88)

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
    .if \software
        mflr 0
    .endif

    stdu 1, -THROW_FRAME_SIZE(1)
    .cfi_def_cfa 1, THROW_FRAME_SIZE

    std 31, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__FP(1)
    std 0,  rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__LR(1)
    std 0,  rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__IP(1)
    std 3,  rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R3(1)
    std 4,  rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R4(1)
    std 5,  rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R5(1)
    std 6,  rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R6(1)
    std 7,  rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R7(1)
    std 8,  rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R8(1)
    std 9,  rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R9(1)
    std 10, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R10(1)
    std 11, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R11(1)
    std 12, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R12(1)
    std 14, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R14(1)
    std 15, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R15(1)
    std 16, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R16(1)
    std 17, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R17(1)
    std 18, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R18(1)
    std 19, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R19(1)
    std 20, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R20(1)
    std 21, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R21(1)
    std 22, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R22(1)
    std 23, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R23(1)
    std 24, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R24(1)
    std 25, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R25(1)
    std 26, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R26(1)
    std 27, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R27(1)
    std 28, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R28(1)
    std 29, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R29(1)
    std 30, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__R30(1)

    .if \software
        std 0, 16(1)
    .else
        mflr 8
        std 8, 16(1)
    .endif
    .cfi_offset 65, 16 - THROW_FRAME_SIZE

    addi 8, 1, THROW_FRAME_SIZE
    std 8, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__SP(1)

    stfd 14, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x00(1)
    stfd 15, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x08(1)
    stfd 16, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x10(1)
    stfd 17, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x18(1)
    stfd 18, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x20(1)
    stfd 19, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x28(1)
    stfd 20, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x30(1)
    stfd 21, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x38(1)
    stfd 22, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x40(1)
    stfd 23, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x48(1)
    stfd 24, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x50(1)
    stfd 25, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x58(1)
    stfd 26, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x60(1)
    stfd 27, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x68(1)
    stfd 28, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x70(1)
    stfd 29, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x78(1)
    stfd 30, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x80(1)
    stfd 31, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__F14 + 0x88(1)
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

.macro SAVE_PRESERVED_REGISTERS regDisplayReg
    ld 12, OFFSETOF__REGDISPLAY__pR14(\regDisplayReg)
    std 14, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR15(\regDisplayReg)
    std 15, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR16(\regDisplayReg)
    std 16, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR17(\regDisplayReg)
    std 17, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR18(\regDisplayReg)
    std 18, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR19(\regDisplayReg)
    std 19, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR20(\regDisplayReg)
    std 20, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR21(\regDisplayReg)
    std 21, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR22(\regDisplayReg)
    std 22, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR23(\regDisplayReg)
    std 23, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR24(\regDisplayReg)
    std 24, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR25(\regDisplayReg)
    std 25, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR26(\regDisplayReg)
    std 26, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR27(\regDisplayReg)
    std 27, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR28(\regDisplayReg)
    std 28, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR29(\regDisplayReg)
    std 29, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR30(\regDisplayReg)
    std 30, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pFP(\regDisplayReg)
    std 31, 0(12)
.endm

.macro TRASH_PRESERVED_REGISTERS_STORAGE regDisplayReg
    li 10, 0
    ld 12, OFFSETOF__REGDISPLAY__pR14(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR15(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR16(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR17(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR18(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR19(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR20(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR21(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR22(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR23(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR24(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR25(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR26(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR27(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR28(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR29(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pR30(\regDisplayReg)
    std 10, 0(12)
    ld 12, OFFSETOF__REGDISPLAY__pFP(\regDisplayReg)
    std 10, 0(12)
.endm

.macro SAVE_FUNCLET_FPRS
    stfd 14, FUNCLET_OFFSET_F14 + 0x00(1)
    stfd 15, FUNCLET_OFFSET_F14 + 0x08(1)
    stfd 16, FUNCLET_OFFSET_F14 + 0x10(1)
    stfd 17, FUNCLET_OFFSET_F14 + 0x18(1)
    stfd 18, FUNCLET_OFFSET_F14 + 0x20(1)
    stfd 19, FUNCLET_OFFSET_F14 + 0x28(1)
    stfd 20, FUNCLET_OFFSET_F14 + 0x30(1)
    stfd 21, FUNCLET_OFFSET_F14 + 0x38(1)
    stfd 22, FUNCLET_OFFSET_F14 + 0x40(1)
    stfd 23, FUNCLET_OFFSET_F14 + 0x48(1)
    stfd 24, FUNCLET_OFFSET_F14 + 0x50(1)
    stfd 25, FUNCLET_OFFSET_F14 + 0x58(1)
    stfd 26, FUNCLET_OFFSET_F14 + 0x60(1)
    stfd 27, FUNCLET_OFFSET_F14 + 0x68(1)
    stfd 28, FUNCLET_OFFSET_F14 + 0x70(1)
    stfd 29, FUNCLET_OFFSET_F14 + 0x78(1)
    stfd 30, FUNCLET_OFFSET_F14 + 0x80(1)
    stfd 31, FUNCLET_OFFSET_F14 + 0x88(1)
.endm

.macro RESTORE_FUNCLET_FPRS
    lfd 14, FUNCLET_OFFSET_F14 + 0x00(1)
    lfd 15, FUNCLET_OFFSET_F14 + 0x08(1)
    lfd 16, FUNCLET_OFFSET_F14 + 0x10(1)
    lfd 17, FUNCLET_OFFSET_F14 + 0x18(1)
    lfd 18, FUNCLET_OFFSET_F14 + 0x20(1)
    lfd 19, FUNCLET_OFFSET_F14 + 0x28(1)
    lfd 20, FUNCLET_OFFSET_F14 + 0x30(1)
    lfd 21, FUNCLET_OFFSET_F14 + 0x38(1)
    lfd 22, FUNCLET_OFFSET_F14 + 0x40(1)
    lfd 23, FUNCLET_OFFSET_F14 + 0x48(1)
    lfd 24, FUNCLET_OFFSET_F14 + 0x50(1)
    lfd 25, FUNCLET_OFFSET_F14 + 0x58(1)
    lfd 26, FUNCLET_OFFSET_F14 + 0x60(1)
    lfd 27, FUNCLET_OFFSET_F14 + 0x68(1)
    lfd 28, FUNCLET_OFFSET_F14 + 0x70(1)
    lfd 29, FUNCLET_OFFSET_F14 + 0x78(1)
    lfd 30, FUNCLET_OFFSET_F14 + 0x80(1)
    lfd 31, FUNCLET_OFFSET_F14 + 0x88(1)
.endm

.macro SAVE_FUNCLET_GPRS
    std 31, FUNCLET_OFFSET_FP(1)
    std 0,  FUNCLET_OFFSET_LR(1)
    std 14, FUNCLET_OFFSET_R14 + 0x00(1)
    std 15, FUNCLET_OFFSET_R14 + 0x08(1)
    std 16, FUNCLET_OFFSET_R14 + 0x10(1)
    std 17, FUNCLET_OFFSET_R14 + 0x18(1)
    std 18, FUNCLET_OFFSET_R14 + 0x20(1)
    std 19, FUNCLET_OFFSET_R14 + 0x28(1)
    std 20, FUNCLET_OFFSET_R14 + 0x30(1)
    std 21, FUNCLET_OFFSET_R14 + 0x38(1)
    std 22, FUNCLET_OFFSET_R14 + 0x40(1)
    std 23, FUNCLET_OFFSET_R14 + 0x48(1)
    std 24, FUNCLET_OFFSET_R14 + 0x50(1)
    std 25, FUNCLET_OFFSET_R14 + 0x58(1)
    std 26, FUNCLET_OFFSET_R14 + 0x60(1)
    std 27, FUNCLET_OFFSET_R14 + 0x68(1)
    std 28, FUNCLET_OFFSET_R14 + 0x70(1)
    std 29, FUNCLET_OFFSET_R14 + 0x78(1)
    std 30, FUNCLET_OFFSET_R14 + 0x80(1)
.endm

.macro RESTORE_FUNCLET_GPRS
    ld 14, FUNCLET_OFFSET_R14 + 0x00(1)
    ld 15, FUNCLET_OFFSET_R14 + 0x08(1)
    ld 16, FUNCLET_OFFSET_R14 + 0x10(1)
    ld 17, FUNCLET_OFFSET_R14 + 0x18(1)
    ld 18, FUNCLET_OFFSET_R14 + 0x20(1)
    ld 19, FUNCLET_OFFSET_R14 + 0x28(1)
    ld 20, FUNCLET_OFFSET_R14 + 0x30(1)
    ld 21, FUNCLET_OFFSET_R14 + 0x38(1)
    ld 22, FUNCLET_OFFSET_R14 + 0x40(1)
    ld 23, FUNCLET_OFFSET_R14 + 0x48(1)
    ld 24, FUNCLET_OFFSET_R14 + 0x50(1)
    ld 25, FUNCLET_OFFSET_R14 + 0x58(1)
    ld 26, FUNCLET_OFFSET_R14 + 0x60(1)
    ld 27, FUNCLET_OFFSET_R14 + 0x68(1)
    ld 28, FUNCLET_OFFSET_R14 + 0x70(1)
    ld 29, FUNCLET_OFFSET_R14 + 0x78(1)
    ld 30, FUNCLET_OFFSET_R14 + 0x80(1)
    ld 31, FUNCLET_OFFSET_FP(1)
    ld 0, FUNCLET_OFFSET_LR(1)
    mtlr 0
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
    addi 12, 1, THROW_FRAME_SIZE
    std 12, OFFSETOF__PAL_LIMITED_CONTEXT__SP(15)
    ld 0, OFFSETOF__PAL_LIMITED_CONTEXT__LR(15)
    std 0, OFFSETOF__PAL_LIMITED_CONTEXT__IP(15)
    bl RhThrowHwEx
DEFINE_LABEL RhpThrowHwEx2
    nop
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
    addi 12, 1, THROW_FRAME_SIZE
    std 12, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__SP(1)
    ld 0, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__LR(1)
    std 0, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__IP(1)
    bl RhThrowEx
DEFINE_LABEL RhpThrowImpl2
    nop

    trap
END_FUNC RhpThrowImpl

//
// void RhpRethrow()
//
DEFINE_FUNC RhpRethrow
    STORE_PAL_CONTEXT 1

    addi 14, 1, rsp_offsetof_ExInfo
    addi 15, 1, rsp_offsetof_Context
    li 16, 0
    INIT_EXINFO 14, 15, 16

    bl RhpGetThread
    nop
    mr 16, 3

    ld 3, OFFSETOF__Thread__m_pExInfoStackHead(16)
    std 3, OFFSETOF__ExInfo__m_pPrevExInfo(14)
    std 14, OFFSETOF__Thread__m_pExInfoStackHead(16)

    mr 4, 14
    addi 12, 1, THROW_FRAME_SIZE
    std 12, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__SP(1)
    ld 0, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__LR(1)
    std 0, rsp_offsetof_Context + OFFSETOF__PAL_LIMITED_CONTEXT__IP(1)
    bl RhRethrow
DEFINE_LABEL RhpRethrow2
    nop
    trap
END_FUNC RhpRethrow

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
    TRASH_PRESERVED_REGISTERS_STORAGE 5

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

//
// void RhpCallFinallyFunclet(void* pHandlerIP, REGDISPLAY* pRegDisplay)
//
DEFINE_FUNC RhpCallFinallyFunclet
    mflr 0
    stdu 1, -FUNCLET_FRAME_SIZE(1)
    .cfi_def_cfa 1, FUNCLET_FRAME_SIZE
    .cfi_offset 65, FUNCLET_OFFSET_LR - FUNCLET_FRAME_SIZE
    .cfi_offset 31, FUNCLET_OFFSET_FP - FUNCLET_FRAME_SIZE
    SAVE_FUNCLET_GPRS
    SAVE_FUNCLET_FPRS
    std 3, FUNCLET_OFFSET_HANDLER(1)
    std 4, FUNCLET_OFFSET_REGDISPLAY(1)

    bl RhpGetThread
    nop
    std 3, FUNCLET_OFFSET_THREAD(1)

    lwz 10, OFFSETOF__Thread__m_ThreadStateFlags(3)
    li 11, -17
    and 10, 10, 11
    stw 10, OFFSETOF__Thread__m_ThreadStateFlags(3)

    ld 3, FUNCLET_OFFSET_HANDLER(1)
    ld 4, FUNCLET_OFFSET_REGDISPLAY(1)

    RESTORE_PRESERVED_REGISTERS 4
    TRASH_PRESERVED_REGISTERS_STORAGE 4

    mtctr 3
    bctrl

DEFINE_LABEL RhpCallFinallyFunclet2
    ld 4, FUNCLET_OFFSET_REGDISPLAY(1)
    SAVE_PRESERVED_REGISTERS 4

    ld 5, FUNCLET_OFFSET_THREAD(1)
    lwz 10, OFFSETOF__Thread__m_ThreadStateFlags(5)
    ori 10, 10, TSF_DoNotTriggerGc
    stw 10, OFFSETOF__Thread__m_ThreadStateFlags(5)

    RESTORE_FUNCLET_FPRS
    RESTORE_FUNCLET_GPRS
    addi 1, 1, FUNCLET_FRAME_SIZE
    blr
END_FUNC RhpCallFinallyFunclet

//
// bool RhpCallFilterFunclet(object exceptionObj, void* pFilterIP, REGDISPLAY* pRegDisplay)
//
DEFINE_FUNC RhpCallFilterFunclet
    mflr 0
    stdu 1, -FUNCLET_FRAME_SIZE(1)
    .cfi_def_cfa 1, FUNCLET_FRAME_SIZE
    .cfi_offset 65, FUNCLET_OFFSET_LR - FUNCLET_FRAME_SIZE
    .cfi_offset 31, FUNCLET_OFFSET_FP - FUNCLET_FRAME_SIZE
    SAVE_FUNCLET_GPRS
    SAVE_FUNCLET_FPRS

    ld 12, OFFSETOF__REGDISPLAY__pFP(5)
    ld 31, 0(12)

    mtctr 4
    bctrl

DEFINE_LABEL RhpCallFilterFunclet2
    RESTORE_FUNCLET_FPRS
    RESTORE_FUNCLET_GPRS
    addi 1, 1, FUNCLET_FRAME_SIZE
    blr
END_FUNC RhpCallFilterFunclet

DEFINE_TRAP_HELPER RhpCallPropagateExceptionCallback
