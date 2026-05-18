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

DEFINE_TRAP_HELPER RhpThrowHwEx
DEFINE_TRAP_HELPER RhpThrowHwEx2
DEFINE_TRAP_HELPER RhpThrowExact
DEFINE_TRAP_HELPER RhpThrowEx
DEFINE_TRAP_HELPER RhpThrowImpl
DEFINE_TRAP_HELPER RhpThrowImpl2
DEFINE_TRAP_HELPER RhpRethrow
DEFINE_TRAP_HELPER RhpRethrow2
DEFINE_TRAP_HELPER RhpCallCatchFunclet
DEFINE_TRAP_HELPER RhpCallCatchFunclet2
DEFINE_TRAP_HELPER RhpCallFinallyFunclet
DEFINE_TRAP_HELPER RhpCallFinallyFunclet2
DEFINE_TRAP_HELPER RhpCallFilterFunclet
DEFINE_TRAP_HELPER RhpCallFilterFunclet2
DEFINE_TRAP_HELPER RhpCallPropagateExceptionCallback
