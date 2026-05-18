// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

.abiversion 2
.text

.globl RhpTrapThreads

.macro DEFINE_TRAP_HELPER name
    .p2align 2
    .globl \name
    .type \name,@function
\name:
    trap
    blr
    .size \name, .-\name
.endm

DEFINE_TRAP_HELPER RhpPInvoke
DEFINE_TRAP_HELPER RhpPInvokeReturn
