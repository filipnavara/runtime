// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include <ppc64le/InlineTls.inc>

.macro INLINE_GETTHREAD target
        INLINE_GET_TLS_VAR \target, C_FUNC(t_CurrentThreadInfo)
        ld \target, OFFSETOF__ThreadLocalInfo__m_pThread(\target)
.endm

.macro INLINE_GET_ALLOC_CONTEXT_BASE target
        INLINE_GET_TLS_VAR \target, C_FUNC(t_runtime_thread_locals)
        .if OFFSETOF__RuntimeThreadLocals__ee_alloc_context != 0
                addi \target, \target, OFFSETOF__RuntimeThreadLocals__ee_alloc_context
        .endif
.endm

.set PPC64_COOP_PINVOKE_TRANSITION_BLOCK, 32
.set PPC64_COOP_PINVOKE_FRAME_SIZE, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + SIZEOF__TransitionBlock

.macro PUSH_COOP_PINVOKE_FRAME target
        mflr 0
        stdu 1, -PPC64_COOP_PINVOKE_FRAME_SIZE(1)
        std 2, 24(1)
        std 31, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r31(1)
        std 0,  PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__m_ReturnAddress(1)
        std 14, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r14(1)
        std 15, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r15(1)
        std 16, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r16(1)
        std 17, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r17(1)
        std 18, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r18(1)
        std 19, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r19(1)
        std 20, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r20(1)
        std 21, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r21(1)
        std 22, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r22(1)
        std 23, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r23(1)
        std 24, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r24(1)
        std 25, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r25(1)
        std 26, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r26(1)
        std 27, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r27(1)
        std 28, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r28(1)
        std 29, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r29(1)
        std 30, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r30(1)
        addi \target, 1, PPC64_COOP_PINVOKE_TRANSITION_BLOCK
.endm

.macro POP_COOP_PINVOKE_FRAME
        ld 31, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r31(1)
        ld 0,  PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__m_ReturnAddress(1)
        ld 14, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r14(1)
        ld 15, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r15(1)
        ld 16, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r16(1)
        ld 17, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r17(1)
        ld 18, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r18(1)
        ld 19, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r19(1)
        ld 20, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r20(1)
        ld 21, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r21(1)
        ld 22, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r22(1)
        ld 23, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r23(1)
        ld 24, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r24(1)
        ld 25, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r25(1)
        ld 26, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r26(1)
        ld 27, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r27(1)
        ld 28, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r28(1)
        ld 29, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r29(1)
        ld 30, PPC64_COOP_PINVOKE_TRANSITION_BLOCK + TransitionBlock__r30(1)
        ld 2, 24(1)
        mtlr 0
        addi 1, 1, PPC64_COOP_PINVOKE_FRAME_SIZE
.endm

.macro EPILOG_RETURN
        blr
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

.macro PATCH_LABEL Name
        .global C_FUNC(\Name)
C_FUNC(\Name):
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

.macro LEAF_END_MARKED Name, Section
C_FUNC(\Name\()_End):
        .global C_FUNC(\Name\()_End)
        LEAF_END \Name, \Section
.endm
