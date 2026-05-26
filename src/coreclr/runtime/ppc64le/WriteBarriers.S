// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "AsmMacros_Shared.h"

.abiversion 2
.text

.macro LOAD_GLOBAL target, symbol
    addis \target, 2, \symbol@toc@ha
    ld \target, \symbol@toc@l(\target)
.endm

// On entry:
//   destReg: location already updated
//   refReg:  object reference stored at destReg
//
// On exit:
//   r0, r12: trashed
.macro INSERT_UNCHECKED_WRITE_BARRIER_CORE destReg, refReg
    // Skip the card table write when the stored reference is not in the
    // ephemeral segment.
    LOAD_GLOBAL 12, g_ephemeral_low
    cmpld \refReg, 12
    blt 0f

    LOAD_GLOBAL 12, g_ephemeral_high
    cmpld \refReg, 12
    bge 0f

    // Set this object's card if it has not already been set.
    LOAD_GLOBAL 12, g_card_table
    srdi 0, \destReg, 11
    add 12, 12, 0

    lbz 0, 0(12)
    cmpwi 0, 0xff
    beq 0f

    li 0, 0xff
    stb 0, 0(12)

#ifdef FEATURE_MANUALLY_MANAGED_CARD_BUNDLES
    LOAD_GLOBAL 12, g_card_bundle_table
    srdi 0, \destReg, 21
    add 12, 12, 0

    lbz 0, 0(12)
    cmpwi 0, 0xff
    beq 0f

    li 0, 0xff
    stb 0, 0(12)
#endif

0:
.endm

// On entry:
//   destReg: location already updated
//   refReg:  object reference stored at destReg
//
// On exit:
//   r0, r12: trashed
.macro INSERT_CHECKED_WRITE_BARRIER_CORE destReg, refReg
    LOAD_GLOBAL 12, g_lowest_address
    cmpld \destReg, 12
    blt 0f

    LOAD_GLOBAL 12, g_highest_address
    cmpld \destReg, 12
    bge 0f

    INSERT_UNCHECKED_WRITE_BARRIER_CORE \destReg, \refReg

0:
.endm

// JIT byref write barrier.
//   r9: source address
//   r11: destination address
LEAF_ENTRY RhpByRefAssignRef, _TEXT
ALTERNATE_ENTRY RhpByRefAssignRefAVLocation1
    ld 10, 0(9)
    addi 9, 9, 8
    b RhpCheckedAssignRef
LEAF_END RhpByRefAssignRef, _TEXT

LEAF_ENTRY RhpByRefAssignRefAVLocation2, _TEXT
    trap
    blr
LEAF_END RhpByRefAssignRefAVLocation2, _TEXT

// JIT checked write barrier placeholder.
//   r10: object reference
//   r11: destination address
LEAF_ENTRY RhpCheckedAssignRef, _TEXT
    LOAD_GLOBAL 12, g_lowest_address
    cmpld 11, 12
    blt 0f

    LOAD_GLOBAL 12, g_highest_address
    cmpld 11, 12
    bge 0f

    b RhpAssignRefPpc64le

0:
ALTERNATE_ENTRY RhpCheckedAssignRefAVLocation
    std 10, 0(11)
    addi 11, 11, 8
    blr
LEAF_END RhpCheckedAssignRef, _TEXT

// JIT unchecked write barrier placeholder.
//   r10: object reference
//   r11: destination address
LEAF_ENTRY RhpAssignRefPowerPC64, _TEXT
ALTERNATE_ENTRY RhpAssignRefPpc64le
    sync
ALTERNATE_ENTRY RhpAssignRefAVLocation
    std 10, 0(11)
    INSERT_UNCHECKED_WRITE_BARRIER_CORE 11, 10
    addi 11, 11, 8
    blr
LEAF_END RhpAssignRefPowerPC64, _TEXT

// Standard ABI version used by NativeAOT helper binding.
//   r3: destination address
//   r4: object reference
LEAF_ENTRY RhpAssignRef, _TEXT
    mr 11, 3
    mr 10, 4
    b RhpAssignRefPpc64le
LEAF_END RhpAssignRef, _TEXT

LEAF_ENTRY RhpCheckedLockCmpXchg, _TEXT
ALTERNATE_ENTRY RhpCheckedLockCmpXchgAVLocation
1:
    ldarx 6, 0, 3
    cmpd 6, 5
    bne 2f
    sync
    stdcx. 4, 0, 3
    bne 1b
    sync
    INSERT_CHECKED_WRITE_BARRIER_CORE 3, 4
2:
    sync
    mr 3, 6
    blr
LEAF_END RhpCheckedLockCmpXchg, _TEXT

LEAF_ENTRY RhpCheckedXchg, _TEXT
    sync
ALTERNATE_ENTRY RhpCheckedXchgAVLocation
1:
    ldarx 6, 0, 3
    stdcx. 4, 0, 3
    bne 1b
    sync
    INSERT_CHECKED_WRITE_BARRIER_CORE 3, 4
    mr 3, 6
    blr
LEAF_END RhpCheckedXchg, _TEXT
