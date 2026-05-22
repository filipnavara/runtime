// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

.abiversion 2
.text

.globl FuncEvalHijack
.type FuncEvalHijack,@function
FuncEvalHijack:
    mflr 0
    stdu 1, -32(1)
    std 0, 16(1)
    bl FuncEvalHijackWorker
    nop
    ld 0, 16(1)
    addi 1, 1, 32
    mtlr 0
    mtctr 3
    bctr
    .size FuncEvalHijack, .-FuncEvalHijack

.globl ExceptionHijack
.type ExceptionHijack,@function
ExceptionHijack:
    mflr 0
    stdu 1, -32(1)
    std 0, 16(1)
    bl ExceptionHijackWorker
    nop
    trap
    .size ExceptionHijack, .-ExceptionHijack

