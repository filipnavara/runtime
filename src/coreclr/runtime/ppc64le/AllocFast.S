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

DEFINE_TRAP_HELPER RhpNewFast
DEFINE_TRAP_HELPER RhpNewFinalizable
DEFINE_TRAP_HELPER RhpNewObject
DEFINE_TRAP_HELPER RhNewString
DEFINE_TRAP_HELPER RhpNewArrayFast
DEFINE_TRAP_HELPER RhpNewPtrArrayFast
DEFINE_TRAP_HELPER RhpNewVariableSizeObject
