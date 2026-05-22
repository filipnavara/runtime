// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "AsmMacros_Shared.h"

.abiversion 2
.text

// Allocate non-array, non-finalizable object. If the allocation doesn't fit into the current thread's
// allocation context then automatically fallback to the slow allocation path.
//  r3 == MethodTable
LEAF_ENTRY RhpNewFast, _TEXT
    mflr 0
    stdu 1, -48(1)
    std 0, 16(1)
    std 14, 24(1)
    std 3, 32(1)

    INLINE_GET_ALLOC_CONTEXT_BASE 3
    ld 14, 32(1)

    lwz 5, OFFSETOF__MethodTable__m_uBaseSize(14)

    ld 6, OFFSETOF__ee_alloc_context + OFFSETOF__ee_alloc_context__alloc_ptr(3)
    cmpdi 6, 0
    beq LOCAL_LABEL(RhpNewFast_RarePath)
    ld 7, OFFSETOF__ee_alloc_context + OFFSETOF__ee_alloc_context__combined_limit(3)
    sub 7, 7, 6
    cmpld 5, 7
    bgt LOCAL_LABEL(RhpNewFast_RarePath)

    add 8, 6, 5
    std 14, OFFSETOF__Object__m_pEEType(6)
    std 8, OFFSETOF__ee_alloc_context + OFFSETOF__ee_alloc_context__alloc_ptr(3)
    mr 3, 6

    ld 14, 24(1)
    ld 0, 16(1)
    mtlr 0
    addi 1, 1, 48
    blr

LOCAL_LABEL(RhpNewFast_RarePath):
    mr 3, 14
    li 4, 0
    ld 14, 24(1)
    ld 0, 16(1)
    mtlr 0
    addi 1, 1, 48
    b C_FUNC(RhpNewObject)
LEAF_END RhpNewFast, _TEXT

// Allocate non-array object with finalizer.
//  r3 == MethodTable
LEAF_ENTRY RhpNewFinalizable, _TEXT
    li 4, GC_ALLOC_FINALIZE
    b C_FUNC(RhpNewObject)
LEAF_END RhpNewFinalizable, _TEXT

// Allocate non-array object.
//  r3 == MethodTable
//  r4 == alloc flags
NESTED_ENTRY RhpNewObject, _TEXT, NoHandler
    PUSH_COOP_PINVOKE_FRAME 6

    mr 14, 3
    li 5, 0

    // void* RhpGcAlloc(MethodTable *pEEType, uint32_t uFlags, intptr_t numElements, void * pTransitionFrame)
    bl C_FUNC(RhpGcAlloc)
    nop

    cmpdi 3, 0
    beq LOCAL_LABEL(NewOutOfMemory)

    POP_COOP_PINVOKE_FRAME
    EPILOG_RETURN

LOCAL_LABEL(NewOutOfMemory):
    mr 3, 14
    li 4, 0

    POP_COOP_PINVOKE_FRAME
    b C_FUNC(RhExceptionHandling_FailedAllocation)
NESTED_END RhpNewObject, _TEXT

// Shared code for RhNewString, RhpNewArrayFast and RhpNewPtrArrayFast.
//  r3 == MethodTable
//  r4 == character/element count
//  r5 == string/array size
.macro NEW_ARRAY_FAST
    mflr 0
    stdu 1, -80(1)
    std 0, 16(1)
    std 14, 24(1)
    std 15, 32(1)
    std 3, 40(1)
    std 4, 48(1)
    std 5, 56(1)

    INLINE_GET_ALLOC_CONTEXT_BASE 3
    ld 14, 40(1)
    ld 15, 48(1)
    ld 5, 56(1)

    ld 6, OFFSETOF__ee_alloc_context + OFFSETOF__ee_alloc_context__alloc_ptr(3)
    cmpdi 6, 0
    beq 1f
    ld 7, OFFSETOF__ee_alloc_context + OFFSETOF__ee_alloc_context__combined_limit(3)
    sub 7, 7, 6
    cmpld 5, 7
    bgt 1f

    add 8, 6, 5
    std 14, OFFSETOF__Object__m_pEEType(6)
    stw 15, OFFSETOF__Array__m_Length(6)
    std 8, OFFSETOF__ee_alloc_context + OFFSETOF__ee_alloc_context__alloc_ptr(3)
    mr 3, 6

    ld 15, 32(1)
    ld 14, 24(1)
    ld 0, 16(1)
    mtlr 0
    addi 1, 1, 80
    blr

1:
    mr 3, 14
    mr 4, 15

    ld 15, 32(1)
    ld 14, 24(1)
    ld 0, 16(1)
    mtlr 0
    addi 1, 1, 80
    b C_FUNC(RhpNewVariableSizeObject)
.endm

// Allocate a string.
//  r3 == MethodTable
//  r4 == character count
LEAF_ENTRY RhNewString, _TEXT
    lis 5, ((MAX_STRING_LENGTH >> 16) & 0xffff)
    ori 5, 5, (MAX_STRING_LENGTH & 0xffff)
    cmpld 4, 5
    bgt LOCAL_LABEL(StringSizeOverflow)

    sldi 5, 4, 1
    addi 5, 5, STRING_BASE_SIZE + 7
    li 8, -8
    and 5, 5, 8

    NEW_ARRAY_FAST

LOCAL_LABEL(StringSizeOverflow):
    li 4, 1
    b C_FUNC(RhExceptionHandling_FailedAllocation)
LEAF_END RhNewString, _TEXT

// Allocate a one dimensional, zero based array.
//  r3 == MethodTable
//  r4 == element count
LEAF_ENTRY RhpNewArrayFast, _TEXT
    lis 5, 0x7fff
    ori 5, 5, 0xffff
    cmpld 4, 5
    bgt LOCAL_LABEL(ArraySizeOverflow)

    lhz 5, OFFSETOF__MethodTable__m_usComponentSize(3)
    mulld 5, 4, 5
    addi 5, 5, SZARRAY_BASE_SIZE + 7
    li 8, -8
    and 5, 5, 8

    NEW_ARRAY_FAST

LOCAL_LABEL(ArraySizeOverflow):
    li 4, 1
    b C_FUNC(RhExceptionHandling_FailedAllocation)
LEAF_END RhpNewArrayFast, _TEXT

// Allocate one dimensional, zero based array of pointer sized elements.
//  r3 == MethodTable
//  r4 == element count
LEAF_ENTRY RhpNewPtrArrayFast, _TEXT
    lis 5, ((0x40000000 / 8) >> 16)
    ori 5, 5, ((0x40000000 / 8) & 0xffff)
    cmpld 4, 5
    bge C_FUNC(RhpNewArrayFast)

    sldi 5, 4, 3
    addi 5, 5, SZARRAY_BASE_SIZE

    NEW_ARRAY_FAST
LEAF_END RhpNewPtrArrayFast, _TEXT

// Allocate variable sized object using the slow path that calls a runtime helper.
//  r3 == MethodTable
//  r4 == element count
NESTED_ENTRY RhpNewVariableSizeObject, _TEXT, NoHandler
    PUSH_COOP_PINVOKE_FRAME 6

    mr 14, 3
    mr 5, 4
    li 4, 0

    // void* RhpGcAlloc(MethodTable *pEEType, uint32_t uFlags, intptr_t numElements, void * pTransitionFrame)
    bl C_FUNC(RhpGcAlloc)
    nop

    cmpdi 3, 0
    beq LOCAL_LABEL(RhpNewVariableSizeObject_OutOfMemory)

    POP_COOP_PINVOKE_FRAME
    EPILOG_RETURN

LOCAL_LABEL(RhpNewVariableSizeObject_OutOfMemory):
    mr 3, 14
    li 4, 0

    POP_COOP_PINVOKE_FRAME
    b C_FUNC(RhExceptionHandling_FailedAllocation)
NESTED_END RhpNewVariableSizeObject, _TEXT
