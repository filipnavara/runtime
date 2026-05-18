// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

.abiversion 2
.text

#define POINTER_SIZE 8
#define COMMON_STUB_FRAME_SIZE 240

.p2align 2
.globl RhCommonStub
.type RhCommonStub,@function
RhCommonStub:
.LRhCommonStub_gep:
    addis 2, 12, .TOC.-.LRhCommonStub_gep@ha
    addi 2, 2, .TOC.-.LRhCommonStub_gep@l
.LRhCommonStub_lep:
    .localentry RhCommonStub, .LRhCommonStub_lep-.LRhCommonStub_gep

    // Custom calling convention:
    //     r11 = address of this thunk's data block.
    // The incoming caller may have arbitrary arguments, so preserve the ABI argument registers
    // while calling RhpGetThunkData to get the TLS slot used by RhGetCurrentThunkContext.
    mflr 0
    stdu 1, -COMMON_STUB_FRAME_SIZE(1)
    std 2, 24(1)
    std 0, 208(1)

    std 3, 32(1)
    std 4, 40(1)
    std 5, 48(1)
    std 6, 56(1)
    std 7, 64(1)
    std 8, 72(1)
    std 9, 80(1)
    std 10, 88(1)
    std 11, 96(1)

    stfd 1, 104(1)
    stfd 2, 112(1)
    stfd 3, 120(1)
    stfd 4, 128(1)
    stfd 5, 136(1)
    stfd 6, 144(1)
    stfd 7, 152(1)
    stfd 8, 160(1)
    stfd 9, 168(1)
    stfd 10, 176(1)
    stfd 11, 184(1)
    stfd 12, 192(1)
    stfd 13, 200(1)

    bl RhpGetThunkData
    nop

    mr 12, 3
    ld 11, 96(1)

    lfd 1, 104(1)
    lfd 2, 112(1)
    lfd 3, 120(1)
    lfd 4, 128(1)
    lfd 5, 136(1)
    lfd 6, 144(1)
    lfd 7, 152(1)
    lfd 8, 160(1)
    lfd 9, 168(1)
    lfd 10, 176(1)
    lfd 11, 184(1)
    lfd 12, 192(1)
    lfd 13, 200(1)

    ld 3, 32(1)
    ld 4, 40(1)
    ld 5, 48(1)
    ld 6, 56(1)
    ld 7, 64(1)
    ld 8, 72(1)
    ld 9, 80(1)
    ld 10, 88(1)

    ld 0, 208(1)
    mtlr 0
    ld 2, 24(1)
    addi 1, 1, COMMON_STUB_FRAME_SIZE

    ld 0, 0(11)
    std 0, 0(12)

    ld 12, POINTER_SIZE(11)
    mtctr 12
    bctr
    .size RhCommonStub, .-RhCommonStub

.p2align 2
.globl RhGetCommonStubAddress
.type RhGetCommonStubAddress,@function
RhGetCommonStubAddress:
    addis 3, 2, RhCommonStub@toc@ha
    addi 3, 3, RhCommonStub@toc@l
    blr
    .size RhGetCommonStubAddress, .-RhGetCommonStubAddress
