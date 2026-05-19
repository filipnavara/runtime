// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

.abiversion 2
.text

.macro DEFINE_TRAP_HELPER name
    .p2align 2
    .globl \name
    .type \name,@function
\name:
    trap
    blr
    .size \name, .-\name
.endm

.globl RhpTrapThreads
.globl RhpGetThread
.globl RhpGcPoll2
.globl RhpWaitForGC2

.set PInvokeTransitionFrame_m_FramePointer, 0
.set PInvokeTransitionFrame_m_RIP, 8
.set PInvokeTransitionFrame_m_pThread, 16
.set PInvokeTransitionFrame_m_Flags, 24
.set PInvokeTransitionFrame_m_PreservedRegs, 32

.set Thread_m_pDeferredTransitionFrame, 80
.set Thread_m_ppvHijackedReturnAddressLocation, 104
.set Thread_m_pvHijackedReturnAddress, 112

.set GCPOLL_FRAME_SIZE, 192
.set GCPOLL_FRAME_SAVE_FLAGS_HI16, 4
.set GCPOLL_FRAME_SAVE_FLAGS_LO16, -1

.set PPC64_CALL_FRAME_SIZE, 256

.set PROBE_FRAME_SIZE, 352
.set PROBE_FLAGS_SAVE_PRESERVED_R14_R30, 0x000000000001ffff
.set PROBE_FLAGS_SAVE_SP,                0x0000000000020000
.set PROBE_FLAGS_SAVE_R3_R10,            0x000000000ff00000
.set PROBE_FLAGS_THREAD_HIJACK,          0x0000000200000000
.set PROBE_FLAGS,                        (PROBE_FLAGS_SAVE_PRESERVED_R14_R30 + PROBE_FLAGS_SAVE_SP + PROBE_FLAGS_SAVE_R3_R10 + PROBE_FLAGS_THREAD_HIJACK)

.set HIJACK_FIXUP_FRAME_SIZE, 256
.set HIJACK_FIXUP_R3, 64
.set HIJACK_FIXUP_F1, 128

.macro SAVE_R3_R10 base
    std 3,  HIJACK_FIXUP_R3+0(\base)
    std 4,  HIJACK_FIXUP_R3+8(\base)
    std 5,  HIJACK_FIXUP_R3+16(\base)
    std 6,  HIJACK_FIXUP_R3+24(\base)
    std 7,  HIJACK_FIXUP_R3+32(\base)
    std 8,  HIJACK_FIXUP_R3+40(\base)
    std 9,  HIJACK_FIXUP_R3+48(\base)
    std 10, HIJACK_FIXUP_R3+56(\base)
.endm

.macro RESTORE_R3_R10 base
    ld 3,  HIJACK_FIXUP_R3+0(\base)
    ld 4,  HIJACK_FIXUP_R3+8(\base)
    ld 5,  HIJACK_FIXUP_R3+16(\base)
    ld 6,  HIJACK_FIXUP_R3+24(\base)
    ld 7,  HIJACK_FIXUP_R3+32(\base)
    ld 8,  HIJACK_FIXUP_R3+40(\base)
    ld 9,  HIJACK_FIXUP_R3+48(\base)
    ld 10, HIJACK_FIXUP_R3+56(\base)
.endm

.macro SAVE_F1_F13 base, start
    stfd 1,  \start+0(\base)
    stfd 2,  \start+8(\base)
    stfd 3,  \start+16(\base)
    stfd 4,  \start+24(\base)
    stfd 5,  \start+32(\base)
    stfd 6,  \start+40(\base)
    stfd 7,  \start+48(\base)
    stfd 8,  \start+56(\base)
    stfd 9,  \start+64(\base)
    stfd 10, \start+72(\base)
    stfd 11, \start+80(\base)
    stfd 12, \start+88(\base)
    stfd 13, \start+96(\base)
.endm

.macro RESTORE_F1_F13 base, start
    lfd 1,  \start+0(\base)
    lfd 2,  \start+8(\base)
    lfd 3,  \start+16(\base)
    lfd 4,  \start+24(\base)
    lfd 5,  \start+32(\base)
    lfd 6,  \start+40(\base)
    lfd 7,  \start+48(\base)
    lfd 8,  \start+56(\base)
    lfd 9,  \start+64(\base)
    lfd 10, \start+72(\base)
    lfd 11, \start+80(\base)
    lfd 12, \start+88(\base)
    lfd 13, \start+96(\base)
.endm

.macro INLINE_GETTHREAD_PPC64LE target
    addis \target, 13, tls_CurrentThread@tprel@ha
    addi \target, \target, tls_CurrentThread@tprel@l
.endm

.macro FixupHijackedCallstack
    INLINE_GETTHREAD_PPC64LE 11
    ld 0, Thread_m_pvHijackedReturnAddress(11)
    mtlr 0
    li 12, 0
    std 12, Thread_m_ppvHijackedReturnAddressLocation(11)
    std 12, Thread_m_pvHijackedReturnAddress(11)
.endm

.macro SAVE_PRESERVED_R14_R30 base
    std 14, PInvokeTransitionFrame_m_PreservedRegs+0(\base)
    std 15, PInvokeTransitionFrame_m_PreservedRegs+8(\base)
    std 16, PInvokeTransitionFrame_m_PreservedRegs+16(\base)
    std 17, PInvokeTransitionFrame_m_PreservedRegs+24(\base)
    std 18, PInvokeTransitionFrame_m_PreservedRegs+32(\base)
    std 19, PInvokeTransitionFrame_m_PreservedRegs+40(\base)
    std 20, PInvokeTransitionFrame_m_PreservedRegs+48(\base)
    std 21, PInvokeTransitionFrame_m_PreservedRegs+56(\base)
    std 22, PInvokeTransitionFrame_m_PreservedRegs+64(\base)
    std 23, PInvokeTransitionFrame_m_PreservedRegs+72(\base)
    std 24, PInvokeTransitionFrame_m_PreservedRegs+80(\base)
    std 25, PInvokeTransitionFrame_m_PreservedRegs+88(\base)
    std 26, PInvokeTransitionFrame_m_PreservedRegs+96(\base)
    std 27, PInvokeTransitionFrame_m_PreservedRegs+104(\base)
    std 28, PInvokeTransitionFrame_m_PreservedRegs+112(\base)
    std 29, PInvokeTransitionFrame_m_PreservedRegs+120(\base)
    std 30, PInvokeTransitionFrame_m_PreservedRegs+128(\base)
.endm

.macro RESTORE_PRESERVED_R14_R30 base
    ld 14, PInvokeTransitionFrame_m_PreservedRegs+0(\base)
    ld 15, PInvokeTransitionFrame_m_PreservedRegs+8(\base)
    ld 16, PInvokeTransitionFrame_m_PreservedRegs+16(\base)
    ld 17, PInvokeTransitionFrame_m_PreservedRegs+24(\base)
    ld 18, PInvokeTransitionFrame_m_PreservedRegs+32(\base)
    ld 19, PInvokeTransitionFrame_m_PreservedRegs+40(\base)
    ld 20, PInvokeTransitionFrame_m_PreservedRegs+48(\base)
    ld 21, PInvokeTransitionFrame_m_PreservedRegs+56(\base)
    ld 22, PInvokeTransitionFrame_m_PreservedRegs+64(\base)
    ld 23, PInvokeTransitionFrame_m_PreservedRegs+72(\base)
    ld 24, PInvokeTransitionFrame_m_PreservedRegs+80(\base)
    ld 25, PInvokeTransitionFrame_m_PreservedRegs+88(\base)
    ld 26, PInvokeTransitionFrame_m_PreservedRegs+96(\base)
    ld 27, PInvokeTransitionFrame_m_PreservedRegs+104(\base)
    ld 28, PInvokeTransitionFrame_m_PreservedRegs+112(\base)
    ld 29, PInvokeTransitionFrame_m_PreservedRegs+120(\base)
    ld 30, PInvokeTransitionFrame_m_PreservedRegs+128(\base)
.endm

.p2align 2
.globl RhpGcProbeHijack
.type RhpGcProbeHijack,@function
RhpGcProbeHijack:
    FixupHijackedCallstack

    addis 12, 2, RhpTrapThreads@toc@ha
    lwz 12, RhpTrapThreads@toc@l(12)
    andi. 12, 12, 1
    bne 1f

    blr

1:
    li 12, ((PROBE_FLAGS >> 32) & 0xffff)
    sldi 12, 12, 32
    oris 12, 12, ((PROBE_FLAGS >> 16) & 0xffff)
    ori 12, 12, (PROBE_FLAGS & 0xffff)
    b RhpWaitForGC
    .size RhpGcProbeHijack, .-RhpGcProbeHijack

.p2align 2
.globl RhpWaitForGC
.type RhpWaitForGC,@function
RhpWaitForGC:
    mflr 0
    stdu 1, -PROBE_FRAME_SIZE(1)

    std 31, PInvokeTransitionFrame_m_FramePointer(1)
    std 0, PInvokeTransitionFrame_m_RIP(1)
    std 11, PInvokeTransitionFrame_m_pThread(1)
    std 12, PInvokeTransitionFrame_m_Flags(1)

    SAVE_PRESERVED_R14_R30 1
    addi 0, 1, PROBE_FRAME_SIZE
    std 0, PInvokeTransitionFrame_m_PreservedRegs+136(1)

    std 3,  PInvokeTransitionFrame_m_PreservedRegs+144(1)
    std 4,  PInvokeTransitionFrame_m_PreservedRegs+152(1)
    std 5,  PInvokeTransitionFrame_m_PreservedRegs+160(1)
    std 6,  PInvokeTransitionFrame_m_PreservedRegs+168(1)
    std 7,  PInvokeTransitionFrame_m_PreservedRegs+176(1)
    std 8,  PInvokeTransitionFrame_m_PreservedRegs+184(1)
    std 9,  PInvokeTransitionFrame_m_PreservedRegs+192(1)
    std 10, PInvokeTransitionFrame_m_PreservedRegs+200(1)

    SAVE_F1_F13 1, PInvokeTransitionFrame_m_PreservedRegs+208

    std 1, Thread_m_pDeferredTransitionFrame(11)
    mr 3, 1
    stdu 1, -PPC64_CALL_FRAME_SIZE(1)
    bl RhpWaitForGC2
    nop
    addi 1, 1, PPC64_CALL_FRAME_SIZE

    RESTORE_F1_F13 1, PInvokeTransitionFrame_m_PreservedRegs+208

    ld 3,  PInvokeTransitionFrame_m_PreservedRegs+144(1)
    ld 4,  PInvokeTransitionFrame_m_PreservedRegs+152(1)
    ld 5,  PInvokeTransitionFrame_m_PreservedRegs+160(1)
    ld 6,  PInvokeTransitionFrame_m_PreservedRegs+168(1)
    ld 7,  PInvokeTransitionFrame_m_PreservedRegs+176(1)
    ld 8,  PInvokeTransitionFrame_m_PreservedRegs+184(1)
    ld 9,  PInvokeTransitionFrame_m_PreservedRegs+192(1)
    ld 10, PInvokeTransitionFrame_m_PreservedRegs+200(1)

    RESTORE_PRESERVED_R14_R30 1
    ld 0, PInvokeTransitionFrame_m_RIP(1)
    ld 31, PInvokeTransitionFrame_m_FramePointer(1)

    addi 1, 1, PROBE_FRAME_SIZE
    mtlr 0
    blr
    .size RhpWaitForGC, .-RhpWaitForGC

.p2align 2
.globl RhpGcPoll
.type RhpGcPoll,@function
RhpGcPoll:
    addis 12, 2, RhpTrapThreads@toc@ha
    lwz 12, RhpTrapThreads@toc@l(12)
    cmpwi 12, 0
    bne 1f
    blr
1:
    b RhpGcPollRare
    .size RhpGcPoll, .-RhpGcPoll

.p2align 2
.globl RhpGcPollRare
.type RhpGcPollRare,@function
RhpGcPollRare:
    mflr 0
    stdu 1, -GCPOLL_FRAME_SIZE(1)

    std 31, PInvokeTransitionFrame_m_FramePointer(1)
    std 0, PInvokeTransitionFrame_m_RIP(1)
    li 12, 0
    std 12, PInvokeTransitionFrame_m_pThread(1)

    lis 12, GCPOLL_FRAME_SAVE_FLAGS_HI16
    addi 12, 12, GCPOLL_FRAME_SAVE_FLAGS_LO16
    std 12, PInvokeTransitionFrame_m_Flags(1)

    SAVE_PRESERVED_R14_R30 1
    addi 0, 1, GCPOLL_FRAME_SIZE
    std 0, PInvokeTransitionFrame_m_PreservedRegs+136(1)

    mr 3, 1
    stdu 1, -PPC64_CALL_FRAME_SIZE(1)
    bl RhpGcPoll2
    nop
    addi 1, 1, PPC64_CALL_FRAME_SIZE

    RESTORE_PRESERVED_R14_R30 1
    ld 0, PInvokeTransitionFrame_m_RIP(1)
    ld 31, PInvokeTransitionFrame_m_FramePointer(1)

    addi 1, 1, GCPOLL_FRAME_SIZE
    mtlr 0
    blr
    .size RhpGcPollRare, .-RhpGcPollRare

#ifdef FEATURE_GC_STRESS
DEFINE_TRAP_HELPER RhpGcStressHijack
#endif
