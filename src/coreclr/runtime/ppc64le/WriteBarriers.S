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

// JIT byref write barrier.
//   r10: source address
//   r11: destination address
DEFINE_FUNC RhpByRefAssignRef
DEFINE_FUNC RhpByRefAssignRefAVLocation1
    ld 10, 0(10)
    addi 10, 10, 8
    b RhpCheckedAssignRef
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
    addi 11, 11, 8
    blr
END_FUNC RhpCheckedAssignRefAVLocation
END_FUNC RhpCheckedAssignRef

// JIT unchecked write barrier placeholder.
//   r10: object reference
//   r11: destination address
DEFINE_FUNC RhpAssignRefPowerPC64
DEFINE_FUNC RhpAssignRefPpc64le
DEFINE_FUNC RhpAssignRefAVLocation
    std 10, 0(11)
    addi 11, 11, 8
    blr
END_FUNC RhpAssignRefAVLocation
END_FUNC RhpAssignRefPpc64le
END_FUNC RhpAssignRefPowerPC64

// Standard ABI version used by NativeAOT helper binding.
//   r3: destination address
//   r4: object reference
DEFINE_FUNC RhpAssignRef
    std 4, 0(3)
    blr
END_FUNC RhpAssignRef

DEFINE_FUNC RhpCheckedLockCmpXchg
DEFINE_FUNC RhpCheckedLockCmpXchgAVLocation
    trap
    blr
END_FUNC RhpCheckedLockCmpXchgAVLocation
END_FUNC RhpCheckedLockCmpXchg

DEFINE_FUNC RhpCheckedXchg
DEFINE_FUNC RhpCheckedXchgAVLocation
    trap
    blr
END_FUNC RhpCheckedXchgAVLocation
END_FUNC RhpCheckedXchg
