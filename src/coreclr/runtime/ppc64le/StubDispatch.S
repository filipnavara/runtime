// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "AsmOffsets.inc"

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

.macro DEFINE_ALT_ENTRY name
    .globl \name
    .type \name,@function
\name:
.endm

.macro CHECK_CACHE_ENTRY entry
    ld 0, (OFFSETOF__InterfaceDispatchCache__m_rgEntries + (\entry * SIZEOF__InterfaceDispatchCacheEntry))(11)
    cmpd 10, 0
    bne 0f
    ld 11, (OFFSETOF__InterfaceDispatchCache__m_rgEntries + (\entry * SIZEOF__InterfaceDispatchCacheEntry) + 8)(11)
    cmpdi 11, 0
    beq 0f
    mtctr 11
    bctr
0:
.endm

.macro DEFINE_INTERFACE_DISPATCH_STUB entries
DEFINE_FUNC RhpInterfaceDispatch\entries
    // r12 holds the indirection cell address. Keep it live for the slow path.
    ld 11, OFFSETOF__InterfaceDispatchCell__m_pCache(12)

    // Retry through the cell if this stub observes a stale non-cache value or a
    // cache with a different entry count.
    andi. 0, 11, IDC_CACHE_POINTER_MASK
    bne .LRaceRetry_\entries
    lwz 0, OFFSETOF__InterfaceDispatchCache__m_cEntries(11)
    cmpwi 0, \entries
    bne .LRaceRetry_\entries

DEFINE_ALT_ENTRY RhpInterfaceDispatchAVLocation\entries
    ld 10, 0(3)

    .set CurrentEntry, 0
    .rept \entries
        CHECK_CACHE_ENTRY CurrentEntry
        .set CurrentEntry, CurrentEntry + 1
    .endr

    b RhpInterfaceDispatchSlow

.LRaceRetry_\entries:
    ld 11, 0(12)
    mtctr 11
    bctr
END_FUNC RhpInterfaceDispatch\entries
.endm

DEFINE_INTERFACE_DISPATCH_STUB 1
DEFINE_INTERFACE_DISPATCH_STUB 2
DEFINE_INTERFACE_DISPATCH_STUB 4
DEFINE_INTERFACE_DISPATCH_STUB 8
DEFINE_INTERFACE_DISPATCH_STUB 16
DEFINE_INTERFACE_DISPATCH_STUB 32
DEFINE_INTERFACE_DISPATCH_STUB 64

DEFINE_FUNC RhpInitialInterfaceDispatch
DEFINE_ALT_ENTRY RhpInitialDynamicInterfaceDispatch
    // Trigger an AV if the instance is null. The exception handling code knows
    // this is the dispatch helper AV location.
    ld 0, 0(3)
    b RhpInterfaceDispatchSlow
END_FUNC RhpInitialInterfaceDispatch

DEFINE_FUNC RhpInterfaceDispatchSlow
    // r12 contains the interface dispatch cell. RhpUniversalTransitionTailCall
    // expects r11 to contain the resolver target and r12 to contain its argument.
    addis 11, 2, RhpCidResolve@toc@ha
    addi 11, 11, RhpCidResolve@toc@l
    b RhpUniversalTransitionTailCall
END_FUNC RhpInterfaceDispatchSlow
