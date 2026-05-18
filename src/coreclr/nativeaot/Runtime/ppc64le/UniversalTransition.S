// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

.abiversion 2
.text

#ifdef _DEBUG
.data
.p2align 3
.globl RhpIntegerTrashValues
RhpIntegerTrashValues:
    .quad 0
.globl RhpFpTrashValues
RhpFpTrashValues:
    .quad 0
.text
#endif

.p2align 2
.globl RhpUniversalTransitionTailCall
.type RhpUniversalTransitionTailCall,@function
RhpUniversalTransitionTailCall:
    trap
    blr
    .size RhpUniversalTransitionTailCall, .-RhpUniversalTransitionTailCall

.p2align 2
.globl ReturnFromUniversalTransitionTailCall
.type ReturnFromUniversalTransitionTailCall,@function
ReturnFromUniversalTransitionTailCall:
    trap
    blr
    .size ReturnFromUniversalTransitionTailCall, .-ReturnFromUniversalTransitionTailCall
