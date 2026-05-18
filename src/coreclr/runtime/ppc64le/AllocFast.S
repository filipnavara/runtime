// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

.abiversion 2
.text

.macro DEFINE_FUNC name
    .p2align 2
    .globl \name
    .type \name,@function
\name:
.endm

.macro END_FUNC name
    .size \name, .-\name
.endm

.macro PUSH_ALLOC_FRAME
    mflr 0
    stdu 1, -304(1)
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
.endm

.macro POP_ALLOC_FRAME
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
    ld 0, 136(1)
    mtlr 0
    addi 1, 1, 304
.endm

.macro SLOW_OBJECT_ALLOC
    mr 3, 14
    mr 4, 15
    li 5, 0
    addi 6, 1, 128
    bl RhpGcAlloc
    nop
    li 5, 0
    cmpd 3, 5
    beq 1f
    POP_ALLOC_FRAME
    blr

1:
    POP_ALLOC_FRAME
    trap
    blr
.endm

.macro SLOW_ARRAY_ALLOC
    mr 3, 14
    li 4, 0
    mr 5, 15
    addi 6, 1, 128
    bl RhpGcAlloc
    nop
    li 5, 0
    cmpd 3, 5
    beq 1f
    POP_ALLOC_FRAME
    blr

1:
    POP_ALLOC_FRAME
    trap
    blr
.endm

// r3: Thread
// r5: object size
// r14: MethodTable
.macro ALLOC_OBJECT_FAST
    ld 6, 8(3)          // alloc_ptr
    ld 7, 0(3)          // combined_limit
    sub 7, 7, 6
    cmpld 5, 7
    bgt 1f

    add 8, 6, 5
    std 14, 0(6)
    std 8, 8(3)
    mr 3, 6
    POP_ALLOC_FRAME
    blr

1:
    li 15, 0
    SLOW_OBJECT_ALLOC
.endm

// r3: Thread
// r5: object size
// r14: MethodTable
// r15: element count
.macro ALLOC_ARRAY_FAST
    ld 6, 8(3)          // alloc_ptr
    ld 7, 0(3)          // combined_limit
    sub 7, 7, 6
    cmpld 5, 7
    bgt 1f

    add 8, 6, 5
    std 14, 0(6)
    stw 15, 8(6)
    std 8, 8(3)
    mr 3, 6
    POP_ALLOC_FRAME
    blr

1:
    SLOW_ARRAY_ALLOC
.endm

// Allocate a non-array, non-finalizable object.
// r3: MethodTable
DEFINE_FUNC RhpNewFast
    PUSH_ALLOC_FRAME
    mr 14, 3
    bl RhpGetThread
    nop

    lwz 5, 4(14)        // MethodTable::m_uBaseSize
    ALLOC_OBJECT_FAST
END_FUNC RhpNewFast

// Allocate a non-array object. This minimal PPC64LE helper only handles the
// non-finalizable path; finalizable objects need the real slow helper frame.
// r3: MethodTable
// r4: alloc flags
DEFINE_FUNC RhpNewObject
    PUSH_ALLOC_FRAME
    mr 14, 3
    mr 15, 4
    SLOW_OBJECT_ALLOC
END_FUNC RhpNewObject

DEFINE_FUNC RhpNewFinalizable
    PUSH_ALLOC_FRAME
    mr 14, 3
    li 15, 1           // GC_ALLOC_FINALIZE
    SLOW_OBJECT_ALLOC
END_FUNC RhpNewFinalizable

// Allocate a string.
// r3: MethodTable
// r4: character count
DEFINE_FUNC RhNewString
    PUSH_ALLOC_FRAME
    mr 14, 3
    mr 15, 4

    lis 5, 0x3fff
    ori 5, 5, 0xffdf
    cmpld 15, 5
    bgt 1f

    bl RhpGetThread
    nop

    sldi 5, 15, 1
    addi 5, 5, 29       // align(STRING_BASE_SIZE + 2 * length, 8)
    li 8, -8
    and 5, 5, 8
    ALLOC_ARRAY_FAST

1:
    POP_ALLOC_FRAME
    trap
    blr
END_FUNC RhNewString

// Allocate a one dimensional, zero based array.
// r3: MethodTable
// r4: element count
DEFINE_FUNC RhpNewArrayFast
    PUSH_ALLOC_FRAME
    mr 14, 3
    mr 15, 4

    lis 5, 0x7fff
    ori 5, 5, 0xffff
    cmpld 15, 5
    bgt 1f

    bl RhpGetThread
    nop

    lhz 5, 0(14)        // MethodTable::m_usComponentSize
    mulld 5, 15, 5
    addi 5, 5, 31       // align(SZARRAY_BASE_SIZE + componentSize * length, 8)
    li 8, -8
    and 5, 5, 8
    ALLOC_ARRAY_FAST

1:
    POP_ALLOC_FRAME
    trap
    blr
END_FUNC RhpNewArrayFast

DEFINE_FUNC RhpNewPtrArrayFast
    b RhpNewArrayFast
END_FUNC RhpNewPtrArrayFast

DEFINE_FUNC RhpNewVariableSizeObject
    b RhpNewArrayFast
END_FUNC RhpNewVariableSizeObject
