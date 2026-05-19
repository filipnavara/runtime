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

.macro DEFINE_LOCAL_FUNC name
    .globl \name
    .type \name,@function
\name:
.endm

.macro END_FUNC name
    .size \name, .-\name
.endm

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
//   r10: source address
//   r11: destination address
DEFINE_FUNC RhpByRefAssignRef
DEFINE_FUNC RhpByRefAssignRefAVLocation1
    ld 0, 0(10)
    std 0, 0(11)
    INSERT_CHECKED_WRITE_BARRIER_CORE 11, 0
    addi 10, 10, 8
    addi 11, 11, 8
    blr
END_FUNC RhpByRefAssignRefAVLocation1
END_FUNC RhpByRefAssignRef

DEFINE_FUNC RhpByRefAssignRefAVLocation2
    trap
    blr
END_FUNC RhpByRefAssignRefAVLocation2

// JIT checked write barrier placeholder.
//   r10: object reference
//   r11: destination address
DEFINE_FUNC RhpCheckedAssignRef
DEFINE_FUNC RhpCheckedAssignRefAVLocation
    std 10, 0(11)
    INSERT_CHECKED_WRITE_BARRIER_CORE 11, 10
    addi 11, 11, 8
    blr
END_FUNC RhpCheckedAssignRefAVLocation
END_FUNC RhpCheckedAssignRef

// JIT unchecked write barrier placeholder.
//   r10: object reference
//   r11: destination address
DEFINE_FUNC RhpAssignRefPowerPC64
DEFINE_FUNC RhpAssignRefPpc64le
    sync
DEFINE_LOCAL_FUNC RhpAssignRefAVLocation
    std 10, 0(11)
    INSERT_UNCHECKED_WRITE_BARRIER_CORE 11, 10
    addi 11, 11, 8
    blr
END_FUNC RhpAssignRefAVLocation
END_FUNC RhpAssignRefPpc64le
END_FUNC RhpAssignRefPowerPC64

// Standard ABI version used by NativeAOT helper binding.
//   r3: destination address
//   r4: object reference
DEFINE_FUNC RhpAssignRef
    mr 11, 3
    mr 10, 4
    b RhpAssignRefPpc64le
END_FUNC RhpAssignRef

DEFINE_FUNC RhpCheckedLockCmpXchg
DEFINE_FUNC RhpCheckedLockCmpXchgAVLocation
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
END_FUNC RhpCheckedLockCmpXchgAVLocation
END_FUNC RhpCheckedLockCmpXchg

DEFINE_FUNC RhpCheckedXchg
    sync
DEFINE_FUNC RhpCheckedXchgAVLocation
1:
    ldarx 6, 0, 3
    stdcx. 4, 0, 3
    bne 1b
    sync
    INSERT_CHECKED_WRITE_BARRIER_CORE 3, 4
    mr 3, 6
    blr
END_FUNC RhpCheckedXchgAVLocation
END_FUNC RhpCheckedXchg
