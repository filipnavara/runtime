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
.globl RhpGcPoll2

DEFINE_TRAP_HELPER RhpGcProbeHijack
DEFINE_TRAP_HELPER RhpWaitForGC

.p2align 2
.globl RhpGcPoll
.type RhpGcPoll,@function
RhpGcPoll:
    blr
    .size RhpGcPoll, .-RhpGcPoll

DEFINE_TRAP_HELPER RhpGcPollRare

#ifdef FEATURE_GC_STRESS
DEFINE_TRAP_HELPER RhpGcStressHijack
#endif
