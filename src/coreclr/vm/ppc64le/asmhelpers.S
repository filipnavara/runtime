// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "AsmMacros_Shared.h"

.abiversion 2
.text

.set PPC64_CALL_FRAME_TOC_SAVE, 24
.set PPC64_STUB_CODE_PAGE_SIZE, 0x4000

.set PPC64_STUB_PRECODE_PC_OFFSET, 8
.set PPC64_STUB_PRECODE_DATA_DELTA, PPC64_STUB_CODE_PAGE_SIZE - PPC64_STUB_PRECODE_PC_OFFSET
.set PPC64_FIXUP_PRECODE_FAST_PC_OFFSET, 8
.set PPC64_FIXUP_PRECODE_FAST_DATA_DELTA, PPC64_STUB_CODE_PAGE_SIZE - PPC64_FIXUP_PRECODE_FAST_PC_OFFSET
.set PPC64_FIXUP_PRECODE_SLOW_PC_OFFSET, 56
.set PPC64_FIXUP_PRECODE_SLOW_DATA_DELTA, PPC64_STUB_CODE_PAGE_SIZE - PPC64_FIXUP_PRECODE_SLOW_PC_OFFSET

.set PPC64_PRESTUB_TRANSITION_BLOCK, 0xE0
.set PPC64_PRESTUB_FLOAT_ARGUMENT_REGISTERS, PPC64_PRESTUB_TRANSITION_BLOCK - SIZEOF__FloatArgumentRegisters
.set PPC64_PRESTUB_STACK_FRAME_SIZE, PPC64_PRESTUB_TRANSITION_BLOCK + SIZEOF__TransitionBlock
.set PPC64_PRESTUB_IMPORT_SECTION_INDEX_SAVE, 32

.set PPC64_UMENTRY_STACK_FRAME_SIZE, 0x120
.set PPC64_UMENTRY_LR_SAVE, 0x60
.set PPC64_UMENTRY_R31_SAVE, 0x68
.set PPC64_UMENTRY_R3_SAVE, 0x70
.set PPC64_UMENTRY_F1_SAVE, 0xB0
.set PPC64_HIJACK_ARGS_OFFSET, 0x20
.set PPC64_HIJACK_FRAME_SIZE, PPC64_HIJACK_ARGS_OFFSET + SIZEOF__HijackArgs

.macro SAVE_ARGUMENT_REGISTERS base, ofs
    std 3,  \ofs+0(\base)
    std 4,  \ofs+8(\base)
    std 5,  \ofs+16(\base)
    std 6,  \ofs+24(\base)
    std 7,  \ofs+32(\base)
    std 8,  \ofs+40(\base)
    std 9,  \ofs+48(\base)
    std 10, \ofs+56(\base)
.endm

.macro RESTORE_ARGUMENT_REGISTERS base, ofs
    ld 3,  \ofs+0(\base)
    ld 4,  \ofs+8(\base)
    ld 5,  \ofs+16(\base)
    ld 6,  \ofs+24(\base)
    ld 7,  \ofs+32(\base)
    ld 8,  \ofs+40(\base)
    ld 9,  \ofs+48(\base)
    ld 10, \ofs+56(\base)
.endm

.macro SAVE_FLOAT_ARGUMENT_REGISTERS base, ofs
    stfd 1,  \ofs+0(\base)
    stfd 2,  \ofs+8(\base)
    stfd 3,  \ofs+16(\base)
    stfd 4,  \ofs+24(\base)
    stfd 5,  \ofs+32(\base)
    stfd 6,  \ofs+40(\base)
    stfd 7,  \ofs+48(\base)
    stfd 8,  \ofs+56(\base)
    stfd 9,  \ofs+64(\base)
    stfd 10, \ofs+72(\base)
    stfd 11, \ofs+80(\base)
    stfd 12, \ofs+88(\base)
    stfd 13, \ofs+96(\base)
.endm

.macro RESTORE_FLOAT_ARGUMENT_REGISTERS base, ofs
    lfd 1,  \ofs+0(\base)
    lfd 2,  \ofs+8(\base)
    lfd 3,  \ofs+16(\base)
    lfd 4,  \ofs+24(\base)
    lfd 5,  \ofs+32(\base)
    lfd 6,  \ofs+40(\base)
    lfd 7,  \ofs+48(\base)
    lfd 8,  \ofs+56(\base)
    lfd 9,  \ofs+64(\base)
    lfd 10, \ofs+72(\base)
    lfd 11, \ofs+80(\base)
    lfd 12, \ofs+88(\base)
    lfd 13, \ofs+96(\base)
.endm

.macro SAVE_TRANSITION_BLOCK base
    mflr 0
    std 31, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r31(\base)
    std 0,  PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__m_ReturnAddress(\base)
    std 14, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r14(\base)
    std 15, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r15(\base)
    std 16, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r16(\base)
    std 17, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r17(\base)
    std 18, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r18(\base)
    std 19, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r19(\base)
    std 20, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r20(\base)
    std 21, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r21(\base)
    std 22, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r22(\base)
    std 23, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r23(\base)
    std 24, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r24(\base)
    std 25, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r25(\base)
    std 26, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r26(\base)
    std 27, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r27(\base)
    std 28, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r28(\base)
    std 29, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r29(\base)
    std 30, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r30(\base)
    SAVE_ARGUMENT_REGISTERS \base, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__m_argumentRegisters
    SAVE_FLOAT_ARGUMENT_REGISTERS \base, PPC64_PRESTUB_FLOAT_ARGUMENT_REGISTERS
.endm

.macro RESTORE_TRANSITION_BLOCK_FOR_TAILCALL base
    RESTORE_FLOAT_ARGUMENT_REGISTERS \base, PPC64_PRESTUB_FLOAT_ARGUMENT_REGISTERS
    RESTORE_ARGUMENT_REGISTERS \base, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__m_argumentRegisters
    ld 31, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r31(\base)
    ld 0,  PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__m_ReturnAddress(\base)
    ld 14, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r14(\base)
    ld 15, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r15(\base)
    ld 16, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r16(\base)
    ld 17, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r17(\base)
    ld 18, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r18(\base)
    ld 19, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r19(\base)
    ld 20, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r20(\base)
    ld 21, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r21(\base)
    ld 22, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r22(\base)
    ld 23, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r23(\base)
    ld 24, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r24(\base)
    ld 25, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r25(\base)
    ld 26, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r26(\base)
    ld 27, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r27(\base)
    ld 28, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r28(\base)
    ld 29, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r29(\base)
    ld 30, PPC64_PRESTUB_TRANSITION_BLOCK + TransitionBlock__r30(\base)
    mtlr 0
.endm

.macro ESTABLISH_TOC_FROM_PC label
    bl \label
\label:
    mflr 2
    addis 2, 2, .TOC.-\label@ha
    addi 2, 2, .TOC.-\label@l
.endm

LEAF_ENTRY GetCurrentIP, _TEXT
    mflr 3
    blr
LEAF_END GetCurrentIP, _TEXT

LEAF_ENTRY GetCurrentSP, _TEXT
    mr 3, 1
    blr
LEAF_END GetCurrentSP, _TEXT

NESTED_ENTRY CallDescrWorkerInternal, _TEXT, NoHandler
    mflr 0
    std 0, 16(1)
    std 30, -16(1)
    std 31, -8(1)
    stdu 1, -64(1)
    .cfi_adjust_cfa_offset 64
    std 2, 24(1)
    mfcr 0
    std 0, 32(1)
    .cfi_offset 65, 16
    .cfi_offset 30, -16
    .cfi_offset 31, -8

    mr 31, 3
    mr 30, 1

    lwz 4, CallDescrData__numStackSlots(31)
    cmpwi 4, 0
    beq LOCAL_LABEL(donestack)

    sldi 5, 4, 3
    addi 6, 5, 96
    addi 6, 6, 15
    clrrdi 6, 6, 4
    subf 1, 6, 1

    ld 7, CallDescrData__pSrc(31)
    add 8, 7, 5
    addi 9, 1, 96
    add 9, 9, 5

LOCAL_LABEL(stackloop):
    addi 8, 8, -8
    ld 10, 0(8)
    addi 9, 9, -8
    std 10, 0(9)
    addi 4, 4, -1
    cmpwi 4, 0
    bne LOCAL_LABEL(stackloop)

LOCAL_LABEL(donestack):
    ld 12, CallDescrData__pFloatArgumentRegisters(31)
    cmpdi 12, 0
    beq LOCAL_LABEL(NoFloatingPoint)

    lfd 1, 0(12)
    lfd 2, 8(12)
    lfd 3, 16(12)
    lfd 4, 24(12)
    lfd 5, 32(12)
    lfd 6, 40(12)
    lfd 7, 48(12)
    lfd 8, 56(12)
    lfd 9, 64(12)
    lfd 10, 72(12)
    lfd 11, 80(12)
    lfd 12, 88(12)
    lfd 13, 96(12)

LOCAL_LABEL(NoFloatingPoint):
    ld 12, CallDescrData__pArgumentRegisters(31)
    ld 3, 0(12)
    ld 4, 8(12)
    ld 5, 16(12)
    ld 6, 24(12)
    ld 7, 32(12)
    ld 8, 40(12)
    ld 9, 48(12)
    ld 10, 56(12)

    ld 12, CallDescrData__pTarget(31)
    mtctr 12
    bctrl
LOCAL_LABEL(CallDescrWorkerInternalReturnAddress):

    lwz 5, CallDescrData__fpReturnSize(31)
    cmpwi 5, 0
    beq LOCAL_LABEL(IntReturn)

    stfd 1, CallDescrData__returnValue(31)
    andi. 5, 5, FpStruct__BothFloat
    bne LOCAL_LABEL(SecondFieldFloatReturn)
    std 3, CallDescrData__returnValue + 8(31)
    b LOCAL_LABEL(ReturnDone)

LOCAL_LABEL(SecondFieldFloatReturn):
    stfd 2, CallDescrData__returnValue + 8(31)
    b LOCAL_LABEL(ReturnDone)

LOCAL_LABEL(IntReturn):
    std 3, CallDescrData__returnValue(31)
    std 4, CallDescrData__returnValue + 8(31)

LOCAL_LABEL(ReturnDone):
    mr 1, 30
    ld 0, 32(1)
    mtcrf 0x38, 0
    ld 31, 56(1)
    ld 30, 48(1)
    ld 2, 24(1)
    ld 0, 80(1)
    mtlr 0
    addi 1, 1, 64
    blr

PATCH_LABEL CallDescrWorkerInternalReturnAddressOffset
    .quad LOCAL_LABEL(CallDescrWorkerInternalReturnAddress) - C_FUNC(CallDescrWorkerInternal)
NESTED_END CallDescrWorkerInternal, _TEXT

LEAF_ENTRY JIT_PatchedCodeStart, _TEXT
    blr
LEAF_END JIT_PatchedCodeStart, _TEXT

LEAF_ENTRY JIT_WriteBarrier, _TEXT
    b RhpAssignRefPpc64le
LEAF_END_MARKED JIT_WriteBarrier, _TEXT

LEAF_ENTRY JIT_CheckedWriteBarrier, _TEXT
    b RhpCheckedAssignRef
LEAF_END_MARKED JIT_CheckedWriteBarrier, _TEXT

LEAF_ENTRY JIT_ByRefWriteBarrier, _TEXT
    b RhpByRefAssignRef
LEAF_END_MARKED JIT_ByRefWriteBarrier, _TEXT

LEAF_ENTRY JIT_WriteBarrier_Table, _TEXT
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
LEAF_END_MARKED JIT_WriteBarrier_Table, _TEXT

LEAF_ENTRY JIT_PatchedCodeLast, _TEXT
    blr
LEAF_END JIT_PatchedCodeLast, _TEXT

NESTED_ENTRY ThePreStub, _TEXT, NoHandler
    // Native unwinding can cross this frame if PreStubWorker rethrows a managed
    // exception. Save LR in the caller linkage area before allocating our frame,
    // matching the canonical PPC64 prolog shape used by CallDescrWorkerInternal.
    mflr 0
    std 0, 16(1)
    stdu 1, -PPC64_PRESTUB_STACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_PRESTUB_STACK_FRAME_SIZE
    .cfi_offset 65, 16
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    SAVE_TRANSITION_BLOCK 1
    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(ThePreStubGetPc)

    addi 3, 1, PPC64_PRESTUB_TRANSITION_BLOCK
    mr 4, METHODDESC_REGISTER
    bl C_FUNC(PreStubWorker)
    nop

    mr 12, 3
    ld 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    RESTORE_TRANSITION_BLOCK_FOR_TAILCALL 1
    addi 1, 1, PPC64_PRESTUB_STACK_FRAME_SIZE
    .cfi_adjust_cfa_offset -PPC64_PRESTUB_STACK_FRAME_SIZE
    mtctr 12
    bctr
NESTED_END ThePreStub, _TEXT

NESTED_ENTRY PInvokeImportThunk, _TEXT, NoHandler
    mflr 0
    stdu 1, -PPC64_UMENTRY_STACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_UMENTRY_STACK_FRAME_SIZE
    std 0, PPC64_UMENTRY_LR_SAVE(1)
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    std 31, PPC64_UMENTRY_R31_SAVE(1)

    bl LOCAL_LABEL(PInvokeImportThunkGetPc)
LOCAL_LABEL(PInvokeImportThunkGetPc):
    mflr 2
    addis 2, 2, .TOC.-LOCAL_LABEL(PInvokeImportThunkGetPc)@ha
    addi 2, 2, .TOC.-LOCAL_LABEL(PInvokeImportThunkGetPc)@l

    SAVE_ARGUMENT_REGISTERS 1, PPC64_UMENTRY_R3_SAVE
    SAVE_FLOAT_ARGUMENT_REGISTERS 1, PPC64_UMENTRY_F1_SAVE

    mr 3, METHODDESC_REGISTER
    bl C_FUNC(PInvokeImportWorker)
    nop

    mr 12, 3
    RESTORE_FLOAT_ARGUMENT_REGISTERS 1, PPC64_UMENTRY_F1_SAVE
    RESTORE_ARGUMENT_REGISTERS 1, PPC64_UMENTRY_R3_SAVE
    ld 31, PPC64_UMENTRY_R31_SAVE(1)
    ld 0, PPC64_UMENTRY_LR_SAVE(1)
    mtlr 0
    addi 1, 1, PPC64_UMENTRY_STACK_FRAME_SIZE
    .cfi_adjust_cfa_offset -PPC64_UMENTRY_STACK_FRAME_SIZE
    mtctr 12
    bctr
NESTED_END PInvokeImportThunk, _TEXT

NESTED_ENTRY TheUMEntryPrestub, _TEXT, NoHandler
    mflr 0
    stdu 1, -PPC64_UMENTRY_STACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_UMENTRY_STACK_FRAME_SIZE
    std 0, PPC64_UMENTRY_LR_SAVE(1)
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    std 31, PPC64_UMENTRY_R31_SAVE(1)

    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(TheUMEntryPrestubGetPc)

    SAVE_ARGUMENT_REGISTERS 1, PPC64_UMENTRY_R3_SAVE
    SAVE_FLOAT_ARGUMENT_REGISTERS 1, PPC64_UMENTRY_F1_SAVE

    mr 3, METHODDESC_REGISTER
    bl C_FUNC(TheUMEntryPrestubWorker)
    nop

    mr 12, 3
    RESTORE_FLOAT_ARGUMENT_REGISTERS 1, PPC64_UMENTRY_F1_SAVE
    RESTORE_ARGUMENT_REGISTERS 1, PPC64_UMENTRY_R3_SAVE
    ld 31, PPC64_UMENTRY_R31_SAVE(1)
    ld 0, PPC64_UMENTRY_LR_SAVE(1)
    mtlr 0
    addi 1, 1, PPC64_UMENTRY_STACK_FRAME_SIZE
    .cfi_adjust_cfa_offset -PPC64_UMENTRY_STACK_FRAME_SIZE
    mtctr 12
    bctr
NESTED_END TheUMEntryPrestub, _TEXT

NESTED_ENTRY VarargPInvokeStub, _TEXT, NoHandler
    trap
    blr
NESTED_END VarargPInvokeStub, _TEXT

NESTED_ENTRY VarargPInvokeStub_RetBuffArg, _TEXT, NoHandler
    trap
    blr
NESTED_END VarargPInvokeStub_RetBuffArg, _TEXT

NESTED_ENTRY GenericPInvokeCalliHelper, _TEXT, NoHandler
    // The JIT calls this helper as an ELFv2 function, so r12 contains this
    // helper's entry point on entry. The unmanaged target is passed in r10.
    ld 12, VASigCookie__pPInvokeILStub(11)
    cmpdi 12, 0
    beq C_FUNC(GenericPInvokeCalliGenILStub)

    mtctr 12

    // Tag the unmanaged target secret arg so the generated IL stub can
    // distinguish it from a MethodDesc*. MethodDesc pointers are 8-byte aligned.
    sldi 11, 10, 1
    ori 11, 11, 1

    bctr
NESTED_END GenericPInvokeCalliHelper, _TEXT

NESTED_ENTRY GenericPInvokeCalliGenILStub, _TEXT, NoHandler
    mr 12, 10
    stdu 1, -PPC64_PRESTUB_STACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_PRESTUB_STACK_FRAME_SIZE
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    SAVE_TRANSITION_BLOCK 1
    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(GenericPInvokeCalliGenILStubGetPc)

    // GenericPInvokeCalliStubWorker(TransitionBlock*, VASigCookie*, PCODE)
    addi 3, 1, PPC64_PRESTUB_TRANSITION_BLOCK
    mr 4, 11
    mr 5, 12

    // Keep the helper's hidden registers across the worker call. They are
    // restored before the transition block restores the caller's register state.
    mr 26, 11
    mr 27, 12

    bl C_FUNC(GenericPInvokeCalliStubWorker)
    nop

    mr 11, 26
    mr 12, 27
    RESTORE_TRANSITION_BLOCK_FOR_TAILCALL 1
    mr 10, 12
    ld 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    addi 1, 1, PPC64_PRESTUB_STACK_FRAME_SIZE
    .cfi_adjust_cfa_offset -PPC64_PRESTUB_STACK_FRAME_SIZE
    b C_FUNC(GenericPInvokeCalliHelper)
NESTED_END GenericPInvokeCalliGenILStub, _TEXT

#ifdef FEATURE_READYTORUN

NESTED_ENTRY DelayLoad_MethodCall, _TEXT, NoHandler
    stdu 1, -PPC64_PRESTUB_STACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_PRESTUB_STACK_FRAME_SIZE
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    std 0, PPC64_PRESTUB_IMPORT_SECTION_INDEX_SAVE(1)
    SAVE_TRANSITION_BLOCK 1
    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(DelayLoad_MethodCallGetPc)

    addi 3, 1, PPC64_PRESTUB_TRANSITION_BLOCK
    mr 4, 11
    ld 5, PPC64_PRESTUB_IMPORT_SECTION_INDEX_SAVE(1)
    mr 6, 12
    bl C_FUNC(ExternalMethodFixupWorker)
    nop

    mr 12, 3
    ld 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    RESTORE_TRANSITION_BLOCK_FOR_TAILCALL 1
    addi 1, 1, PPC64_PRESTUB_STACK_FRAME_SIZE
    .cfi_adjust_cfa_offset -PPC64_PRESTUB_STACK_FRAME_SIZE
    mtctr 12
    bctr
NESTED_END DelayLoad_MethodCall, _TEXT

.macro DYNAMIC_HELPER suffix, frameFlags
NESTED_ENTRY DelayLoad_Helper\suffix, _TEXT, NoHandler
    stdu 1, -PPC64_PRESTUB_STACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_PRESTUB_STACK_FRAME_SIZE
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    std 0, PPC64_PRESTUB_IMPORT_SECTION_INDEX_SAVE(1)
    SAVE_TRANSITION_BLOCK 1
    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(DelayLoad_Helper\suffix\()GetPc)

    addi 3, 1, PPC64_PRESTUB_TRANSITION_BLOCK
    mr 4, 11
    ld 5, PPC64_PRESTUB_IMPORT_SECTION_INDEX_SAVE(1)
    mr 6, 12
    li 7, \frameFlags
    bl C_FUNC(DynamicHelperWorker)
    nop

    cmpdi 3, 0
    bne LOCAL_LABEL(DelayLoad_Helper\suffix\()_TailCall)

    ld 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    RESTORE_TRANSITION_BLOCK_FOR_TAILCALL 1
    addi 1, 1, PPC64_PRESTUB_STACK_FRAME_SIZE
    .cfi_adjust_cfa_offset -PPC64_PRESTUB_STACK_FRAME_SIZE
    blr

LOCAL_LABEL(DelayLoad_Helper\suffix\()_TailCall):
    mr 12, 3
    ld 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    RESTORE_TRANSITION_BLOCK_FOR_TAILCALL 1
    addi 1, 1, PPC64_PRESTUB_STACK_FRAME_SIZE
    .cfi_adjust_cfa_offset -PPC64_PRESTUB_STACK_FRAME_SIZE
    mtctr 12
    bctr
NESTED_END DelayLoad_Helper\suffix, _TEXT
.endm

DYNAMIC_HELPER , DynamicHelperFrameFlags_Default
DYNAMIC_HELPER _Obj, DynamicHelperFrameFlags_ObjectArg
DYNAMIC_HELPER _ObjObj, DynamicHelperFrameFlags_ObjectArg2

#endif // FEATURE_READYTORUN

LEAF_ENTRY ThePreStubPatch, _TEXT
PATCH_LABEL ThePreStubPatchLabel
    blr
LEAF_END ThePreStubPatch, _TEXT

LEAF_ENTRY StubPrecodeCode, _TEXT
    mflr 0
    bcl 20, 31, LOCAL_LABEL(StubPrecodeGetPc)
LOCAL_LABEL(StubPrecodeGetPc):
    mflr 12
    mtlr 0
    addi 12, 12, PPC64_STUB_PRECODE_DATA_DELTA
    ld 11, StubPrecodeData__SecretParam(12)
    ld 12, StubPrecodeData__Target(12)
    mtctr 12
    bctr
    trap
LEAF_END_MARKED StubPrecodeCode, _TEXT

LEAF_ENTRY FixupPrecodeCode, _TEXT
    mflr 0
    bcl 20, 31, LOCAL_LABEL(FixupPrecodeFastGetPc)
LOCAL_LABEL(FixupPrecodeFastGetPc):
    mflr 11
    mtlr 0
    addi 11, 11, PPC64_FIXUP_PRECODE_FAST_DATA_DELTA
    ld 12, FixupPrecodeData__Target(11)
    addi 0, 11, -PPC64_STUB_CODE_PAGE_SIZE
    cmpd 12, 0
    beq LOCAL_LABEL(FixupPrecodeSlowPath)
    mtctr 12
    bctr

LOCAL_LABEL(FixupPrecodeSlowPath):
    sync
    mflr 0
    bcl 20, 31, LOCAL_LABEL(FixupPrecodeSlowGetPc)
LOCAL_LABEL(FixupPrecodeSlowGetPc):
    mflr 12
    mtlr 0
    addi 12, 12, PPC64_FIXUP_PRECODE_SLOW_DATA_DELTA
    ld 11, FixupPrecodeData__MethodDesc(12)
    ld 12, FixupPrecodeData__PrecodeFixupThunk(12)
    mtctr 12
    bctr
    trap
LEAF_END_MARKED FixupPrecodeCode, _TEXT

LEAF_ENTRY ThisPtrRetBufPrecodeWorker, _TEXT
    mr 12, 3
    mr 3, 4
    mtctr 12
    bctr
LEAF_END ThisPtrRetBufPrecodeWorker, _TEXT

NESTED_ENTRY ResolveWorkerAsmStub, _TEXT, NoHandler
    stdu 1, -PPC64_PRESTUB_STACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_PRESTUB_STACK_FRAME_SIZE
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    SAVE_TRANSITION_BLOCK 1
    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(ResolveWorkerAsmStubGetPc)

    addi 3, 1, PPC64_PRESTUB_TRANSITION_BLOCK
    clrrdi 4, 11, 2
    mr 5, 12
    andi. 6, 11, 3
    bl C_FUNC(VSD_ResolveWorker)
    nop

    mr 12, 3
    ld 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    RESTORE_TRANSITION_BLOCK_FOR_TAILCALL 1
    addi 1, 1, PPC64_PRESTUB_STACK_FRAME_SIZE
    .cfi_adjust_cfa_offset -PPC64_PRESTUB_STACK_FRAME_SIZE
    mtctr 12
    bctr
NESTED_END ResolveWorkerAsmStub, _TEXT

NESTED_ENTRY ResolveWorkerChainLookupAsmStub, _TEXT, NoHandler
    b C_FUNC(ResolveWorkerAsmStub)
NESTED_END ResolveWorkerChainLookupAsmStub, _TEXT

NESTED_ENTRY ProfileEnterNaked, _TEXT, NoHandler
    blr
NESTED_END ProfileEnterNaked, _TEXT

NESTED_ENTRY ProfileLeaveNaked, _TEXT, NoHandler
    blr
NESTED_END ProfileLeaveNaked, _TEXT

NESTED_ENTRY ProfileTailcallNaked, _TEXT, NoHandler
    blr
NESTED_END ProfileTailcallNaked, _TEXT

NESTED_ENTRY JIT_ProfilerEnterLeaveTailcallStub, _TEXT, NoHandler
    blr
NESTED_END JIT_ProfilerEnterLeaveTailcallStub, _TEXT

NESTED_ENTRY IL_Throw, _TEXT, NoHandler
    stdu 1, -PPC64_PRESTUB_STACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_PRESTUB_STACK_FRAME_SIZE
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    SAVE_TRANSITION_BLOCK 1
    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(IL_ThrowGetPc)

    addi 4, 1, PPC64_PRESTUB_TRANSITION_BLOCK
    bl C_FUNC(IL_Throw_Impl)
    trap
NESTED_END IL_Throw, _TEXT

NESTED_ENTRY IL_Rethrow, _TEXT, NoHandler
    stdu 1, -PPC64_PRESTUB_STACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_PRESTUB_STACK_FRAME_SIZE
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    SAVE_TRANSITION_BLOCK 1
    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(IL_RethrowGetPc)

    addi 3, 1, PPC64_PRESTUB_TRANSITION_BLOCK
    bl C_FUNC(IL_Rethrow_Impl)
    trap
NESTED_END IL_Rethrow, _TEXT

NESTED_ENTRY IL_ThrowExact, _TEXT, NoHandler
    stdu 1, -PPC64_PRESTUB_STACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_PRESTUB_STACK_FRAME_SIZE
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    SAVE_TRANSITION_BLOCK 1
    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(IL_ThrowExactGetPc)

    addi 4, 1, PPC64_PRESTUB_TRANSITION_BLOCK
    bl C_FUNC(IL_ThrowExact_Impl)
    trap
NESTED_END IL_ThrowExact, _TEXT

LEAF_ENTRY JIT_PollGC, _TEXT
    blr
LEAF_END JIT_PollGC, _TEXT

NESTED_ENTRY JIT_PInvokeBegin, _TEXT, NoHandler
    stdu 1, -64(1)
    .cfi_adjust_cfa_offset 64
    mflr 0
    std 0, 48(1)
    .cfi_offset lr, -16
    std 31, 56(1)
    .cfi_offset r31, -8
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)

    mr 31, 3
    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(JIT_PInvokeBeginGetPc)

    li 12, FRAMETYPE_InlinedCallFrame
    std 12, 0(31)

    li 12, 0
    std 12, InlinedCallFrame__m_Datum(31)

    addi 12, 1, 64
    std 12, InlinedCallFrame__m_pCallSiteSP(31)
    std 0, InlinedCallFrame__m_pCallerReturnAddress(31)

    ld 12, 56(1)
    std 12, InlinedCallFrame__m_pCalleeSavedFP(31)

    bl C_FUNC(GetThreadHelper)
    nop

    std 3, InlinedCallFrame__m_pThread(31)

    ld 12, Thread_m_pFrame(3)
    std 12, Frame__m_Next(31)

    std 31, Thread_m_pFrame(3)

    li 12, 0
    stw 12, Thread_m_fPreemptiveGCDisabled(3)

    ld 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    ld 31, 56(1)
    ld 0, 48(1)
    mtlr 0
    addi 1, 1, 64
    .cfi_adjust_cfa_offset -64
    blr
NESTED_END JIT_PInvokeBegin, _TEXT

LEAF_ENTRY JIT_PInvokeEnd, _TEXT
    ld 4, InlinedCallFrame__m_pThread(3)

    li 12, 1
    stw 12, Thread_m_fPreemptiveGCDisabled(4)

    addis 12, 2, g_TrapReturningThreads@toc@ha
    lwz 12, g_TrapReturningThreads@toc@l(12)
    cmpwi 12, 0
    bne LOCAL_LABEL(JIT_PInvokeEndRarePath)

    ld 12, Frame__m_Next(3)
    std 12, Thread_m_pFrame(4)

    blr

LOCAL_LABEL(JIT_PInvokeEndRarePath):
    b C_FUNC(JIT_PInvokeEndRarePath)
LEAF_END JIT_PInvokeEnd, _TEXT

#ifdef FEATURE_ON_STACK_REPLACEMENT
NESTED_ENTRY JIT_Patchpoint, _TEXT, NoHandler
    stdu 1, -PPC64_PRESTUB_STACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_PRESTUB_STACK_FRAME_SIZE
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    SAVE_TRANSITION_BLOCK 1
    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(JIT_PatchpointGetPc)

    addi 3, 1, PPC64_PRESTUB_TRANSITION_BLOCK
    bl C_FUNC(JIT_PatchpointWorkerWorkerWithPolicy)
    nop

    mr 12, 3
    ld 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    RESTORE_TRANSITION_BLOCK_FOR_TAILCALL 1
    addi 1, 1, PPC64_PRESTUB_STACK_FRAME_SIZE
    .cfi_adjust_cfa_offset -PPC64_PRESTUB_STACK_FRAME_SIZE
    mr 3, 12
    blr
NESTED_END JIT_Patchpoint, _TEXT

LEAF_ENTRY JIT_PatchpointForced, _TEXT
    mr 4, 3
    li 3, 0
    b JIT_Patchpoint
LEAF_END JIT_PatchpointForced, _TEXT
#endif

LEAF_ENTRY JIT_GetDynamicGCStaticBase_SingleAppDomain, _TEXT
    // If class is not initialized, tail call GetGCStaticBase.
    ld 4, OFFSETOF__DynamicStaticsInfo__m_pGCStatics(3)
    sync
    andi. 12, 4, 1
    bne LOCAL_LABEL(JIT_GetDynamicGCStaticBase_SingleAppDomain_CallHelper)
    mr 3, 4
    blr

LOCAL_LABEL(JIT_GetDynamicGCStaticBase_SingleAppDomain_CallHelper):
    ld 3, OFFSETOF__DynamicStaticsInfo__m_pMethodTable(3)
    addis 12, 2, g_pGetGCStaticBase@toc@ha
    ld 12, g_pGetGCStaticBase@toc@l(12)
    mtctr 12
    bctr
LEAF_END JIT_GetDynamicGCStaticBase_SingleAppDomain, _TEXT

LEAF_ENTRY JIT_GetDynamicNonGCStaticBase_SingleAppDomain, _TEXT
    // If class is not initialized, tail call GetNonGCStaticBase.
    ld 4, OFFSETOF__DynamicStaticsInfo__m_pNonGCStatics(3)
    sync
    andi. 12, 4, 1
    bne LOCAL_LABEL(JIT_GetDynamicNonGCStaticBase_SingleAppDomain_CallHelper)
    mr 3, 4
    blr

LOCAL_LABEL(JIT_GetDynamicNonGCStaticBase_SingleAppDomain_CallHelper):
    ld 3, OFFSETOF__DynamicStaticsInfo__m_pMethodTable(3)
    addis 12, 2, g_pGetNonGCStaticBase@toc@ha
    ld 12, g_pGetNonGCStaticBase@toc@l(12)
    mtctr 12
    bctr
LEAF_END JIT_GetDynamicNonGCStaticBase_SingleAppDomain, _TEXT

// OnHijackTripThread is reached by replacing a managed return address. Save the
// register state that may contain return values or GC roots, let the VM perform
// the hijack work, then return to the original address written back by the VM.
NESTED_ENTRY OnHijackTripThread, _TEXT, NoHandler
    stdu 1, -PPC64_HIJACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_HIJACK_FRAME_SIZE

    mflr 0
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)

    std 31, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R31(1)
    std 0,  PPC64_HIJACK_ARGS_OFFSET + HijackArgs__Link(1)
    std 14, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R14(1)
    std 15, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R15(1)
    std 16, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R16(1)
    std 17, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R17(1)
    std 18, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R18(1)
    std 19, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R19(1)
    std 20, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R20(1)
    std 21, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R21(1)
    std 22, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R22(1)
    std 23, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R23(1)
    std 24, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R24(1)
    std 25, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R25(1)
    std 26, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R26(1)
    std 27, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R27(1)
    std 28, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R28(1)
    std 29, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R29(1)
    std 30, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R30(1)

    std 3, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R3(1)
    std 4, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R4(1)
    std 5, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R5(1)
    stfd 1, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__F1(1)
    stfd 2, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__F2(1)
    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(OnHijackTripThreadGetPc)

    addi 3, 1, PPC64_HIJACK_ARGS_OFFSET
    bl C_FUNC(OnHijackWorker)
    nop

    ld 2, PPC64_CALL_FRAME_TOC_SAVE(1)

    ld 3, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R3(1)
    ld 4, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R4(1)
    ld 5, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R5(1)
    lfd 1, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__F1(1)
    lfd 2, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__F2(1)

    ld 31, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R31(1)
    ld 0,  PPC64_HIJACK_ARGS_OFFSET + HijackArgs__Link(1)
    ld 14, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R14(1)
    ld 15, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R15(1)
    ld 16, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R16(1)
    ld 17, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R17(1)
    ld 18, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R18(1)
    ld 19, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R19(1)
    ld 20, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R20(1)
    ld 21, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R21(1)
    ld 22, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R22(1)
    ld 23, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R23(1)
    ld 24, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R24(1)
    ld 25, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R25(1)
    ld 26, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R26(1)
    ld 27, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R27(1)
    ld 28, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R28(1)
    ld 29, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R29(1)
    ld 30, PPC64_HIJACK_ARGS_OFFSET + HijackArgs__R30(1)

    mtlr 0
    addi 1, 1, PPC64_HIJACK_FRAME_SIZE
    .cfi_adjust_cfa_offset -PPC64_HIJACK_FRAME_SIZE
    blr
NESTED_END OnHijackTripThread, _TEXT

#ifdef FEATURE_TIERED_COMPILATION
NESTED_ENTRY OnCallCountThresholdReachedStub, _TEXT, NoHandler
    stdu 1, -PPC64_PRESTUB_STACK_FRAME_SIZE(1)
    .cfi_adjust_cfa_offset PPC64_PRESTUB_STACK_FRAME_SIZE
    std 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    SAVE_TRANSITION_BLOCK 1
    ESTABLISH_TOC_FROM_PC LOCAL_LABEL(OnCallCountThresholdReachedStubGetPc)

    addi 3, 1, PPC64_PRESTUB_TRANSITION_BLOCK
    mr 4, 11
    bl C_FUNC(OnCallCountThresholdReached)
    nop

    mr 12, 3
    ld 2, PPC64_CALL_FRAME_TOC_SAVE(1)
    RESTORE_TRANSITION_BLOCK_FOR_TAILCALL 1
    addi 1, 1, PPC64_PRESTUB_STACK_FRAME_SIZE
    .cfi_adjust_cfa_offset -PPC64_PRESTUB_STACK_FRAME_SIZE
    mtctr 12
    bctr
NESTED_END OnCallCountThresholdReachedStub, _TEXT
#endif

// ------------------------------------------------------------------
// size_t GetThreadStaticsVariableOffset()
//
// Return the initial-exec TLS offset of t_ThreadStatics. JIT code adds
// this offset to r13, the PPC64LE thread pointer.
LEAF_ENTRY GetThreadStaticsVariableOffset, _TEXT
    addis 3, 2, t_ThreadStatics@got@tprel@ha
    ld 3, t_ThreadStatics@got@tprel@l(3)
    blr
LEAF_END GetThreadStaticsVariableOffset, _TEXT

NESTED_ENTRY CallEHFunclet, _TEXT, NoHandler
    // Save LR in the caller linkage area. ExecuteFunctionBelowContext can run a
    // native propagation helper below this frame, and that helper owns this
    // frame's linkage slots.
    mflr 0
    std 0, 16(1)
    stdu 1, -192(1)
    .cfi_adjust_cfa_offset 192
    .cfi_offset 65, 16
    std 14, 32(1)
    .cfi_offset r14, -160
    std 15, 40(1)
    .cfi_offset r15, -152
    std 16, 48(1)
    .cfi_offset r16, -144
    std 17, 56(1)
    .cfi_offset r17, -136
    std 18, 64(1)
    .cfi_offset r18, -128
    std 19, 72(1)
    .cfi_offset r19, -120
    std 20, 80(1)
    .cfi_offset r20, -112
    std 21, 88(1)
    .cfi_offset r21, -104
    std 22, 96(1)
    .cfi_offset r22, -96
    std 23, 104(1)
    .cfi_offset r23, -88
    std 24, 112(1)
    .cfi_offset r24, -80
    std 25, 120(1)
    .cfi_offset r25, -72
    std 26, 128(1)
    .cfi_offset r26, -64
    std 27, 136(1)
    .cfi_offset r27, -56
    std 28, 144(1)
    .cfi_offset r28, -48
    std 29, 152(1)
    .cfi_offset r29, -40
    std 30, 160(1)
    .cfi_offset r30, -32
    std 31, 168(1)
    .cfi_offset r31, -24
    std 2, 176(1)
    .cfi_offset r2, -16

    std 1, 0(6)
    ld 14, CONTEXT_R14(5)
    ld 15, CONTEXT_R15(5)
    ld 16, CONTEXT_R16(5)
    ld 17, CONTEXT_R17(5)
    ld 18, CONTEXT_R18(5)
    ld 19, CONTEXT_R19(5)
    ld 20, CONTEXT_R20(5)
    ld 21, CONTEXT_R21(5)
    ld 22, CONTEXT_R22(5)
    ld 23, CONTEXT_R23(5)
    ld 24, CONTEXT_R24(5)
    ld 25, CONTEXT_R25(5)
    ld 26, CONTEXT_R26(5)
    ld 27, CONTEXT_R27(5)
    ld 28, CONTEXT_R28(5)
    ld 29, CONTEXT_R29(5)
    ld 30, CONTEXT_R30(5)
    ld 31, CONTEXT_R31(5)
    mtctr 4
    bctrl

    ld 14, 32(1)
    ld 15, 40(1)
    ld 16, 48(1)
    ld 17, 56(1)
    ld 18, 64(1)
    ld 19, 72(1)
    ld 20, 80(1)
    ld 21, 88(1)
    ld 22, 96(1)
    ld 23, 104(1)
    ld 24, 112(1)
    ld 25, 120(1)
    ld 26, 128(1)
    ld 27, 136(1)
    ld 28, 144(1)
    ld 29, 152(1)
    ld 30, 160(1)
    ld 31, 168(1)
    ld 2, 176(1)
    ld 0, 208(1)
    mtlr 0
    addi 1, 1, 192
    .cfi_adjust_cfa_offset -192
    blr
NESTED_END CallEHFunclet, _TEXT

NESTED_ENTRY CallEHFilterFunclet, _TEXT, NoHandler
    // Save LR in the caller linkage area; this frame's linkage area is reserved
    // for callees used during native exception propagation.
    mflr 0
    std 0, 16(1)
    stdu 1, -96(1)
    .cfi_adjust_cfa_offset 96
    .cfi_offset 65, 16
    std 2, 80(1)
    .cfi_offset r2, -16
    std 31, 88(1)
    .cfi_offset r31, -8

    std 1, 0(6)
    mr 31, 4
    mtctr 5
    bctrl

    ld 31, 88(1)
    ld 2, 80(1)
    ld 0, 112(1)
    mtlr 0
    addi 1, 1, 96
    .cfi_adjust_cfa_offset -96
    blr
NESTED_END CallEHFilterFunclet, _TEXT

NESTED_ENTRY RedirectForThreadAbort, _TEXT, NoHandler
    trap
    blr
NESTED_END RedirectForThreadAbort, _TEXT

LEAF_ENTRY JIT_StackProbe, _TEXT
    blr
LEAF_END_MARKED JIT_StackProbe, _TEXT
