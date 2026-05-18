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

DEFINE_TRAP_HELPER RhpInterfaceDispatch1
DEFINE_TRAP_HELPER RhpInterfaceDispatch2
DEFINE_TRAP_HELPER RhpInterfaceDispatch4
DEFINE_TRAP_HELPER RhpInterfaceDispatch8
DEFINE_TRAP_HELPER RhpInterfaceDispatch16
DEFINE_TRAP_HELPER RhpInterfaceDispatch32
DEFINE_TRAP_HELPER RhpInterfaceDispatch64

DEFINE_TRAP_HELPER RhpInterfaceDispatchAVLocation1
DEFINE_TRAP_HELPER RhpInterfaceDispatchAVLocation2
DEFINE_TRAP_HELPER RhpInterfaceDispatchAVLocation4
DEFINE_TRAP_HELPER RhpInterfaceDispatchAVLocation8
DEFINE_TRAP_HELPER RhpInterfaceDispatchAVLocation16
DEFINE_TRAP_HELPER RhpInterfaceDispatchAVLocation32
DEFINE_TRAP_HELPER RhpInterfaceDispatchAVLocation64

DEFINE_TRAP_HELPER RhpInitialInterfaceDispatch
DEFINE_TRAP_HELPER RhpInitialDynamicInterfaceDispatch
DEFINE_TRAP_HELPER RhpInterfaceDispatchSlow
