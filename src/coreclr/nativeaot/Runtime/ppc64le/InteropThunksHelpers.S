// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

.abiversion 2
.text

.p2align 2
.globl RhCommonStub
.type RhCommonStub,@function
RhCommonStub:
    trap
    blr
    .size RhCommonStub, .-RhCommonStub

.p2align 2
.globl RhGetCommonStubAddress
.type RhGetCommonStubAddress,@function
RhGetCommonStubAddress:
    li 3, 0
    blr
    .size RhGetCommonStubAddress, .-RhGetCommonStubAddress
