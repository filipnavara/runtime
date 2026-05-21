// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

.abiversion 2
.text

#ifdef _DEBUG
.globl RhpIntegerTrashValues
.globl RhpFpTrashValues
#endif

#define COUNT_ARG_REGISTERS 8
#define INTEGER_REGISTER_SIZE 8
#define ARGUMENT_REGISTERS_SIZE (COUNT_ARG_REGISTERS * INTEGER_REGISTER_SIZE)

#define RETURN_BLOCK_SIZE 16

#define COUNT_FLOAT_ARG_REGISTERS 13
#define FLOAT_REGISTER_SIZE 8
#define FLOAT_ARG_REGISTERS_SIZE (COUNT_FLOAT_ARG_REGISTERS * FLOAT_REGISTER_SIZE)

#define PUSHED_FP_SIZE 8
#define PUSHED_LR_SIZE 8
#define ALIGNMENT_PADDING_SIZE 8

#define FLOAT_ARG_OFFSET (PUSHED_FP_SIZE + PUSHED_LR_SIZE)
#define RETURN_BLOCK_OFFSET (FLOAT_ARG_OFFSET + FLOAT_ARG_REGISTERS_SIZE)
#define ARGUMENT_REGISTERS_OFFSET (RETURN_BLOCK_OFFSET + RETURN_BLOCK_SIZE)
#define ALIGNMENT_PADDING_OFFSET (ARGUMENT_REGISTERS_OFFSET + ARGUMENT_REGISTERS_SIZE)
#define DISTANCE_FROM_CHILDSP_TO_RETURN_BLOCK RETURN_BLOCK_OFFSET
#define STACK_SIZE (ARGUMENT_REGISTERS_SIZE + ALIGNMENT_PADDING_SIZE + RETURN_BLOCK_SIZE + FLOAT_ARG_REGISTERS_SIZE + PUSHED_LR_SIZE + PUSHED_FP_SIZE)

.p2align 2
.globl RhpUniversalTransitionTailCall
.type RhpUniversalTransitionTailCall,@function
RhpUniversalTransitionTailCall:
    // r11: target resolver to call
    // r12: pointer-sized argument to pass to the resolver
    mflr 0
    addi 1, 1, -STACK_SIZE
    std 31, 0(1)
    std 0, 8(1)

    stfd 1, FLOAT_ARG_OFFSET(1)
    stfd 2, FLOAT_ARG_OFFSET + 0x08(1)
    stfd 3, FLOAT_ARG_OFFSET + 0x10(1)
    stfd 4, FLOAT_ARG_OFFSET + 0x18(1)
    stfd 5, FLOAT_ARG_OFFSET + 0x20(1)
    stfd 6, FLOAT_ARG_OFFSET + 0x28(1)
    stfd 7, FLOAT_ARG_OFFSET + 0x30(1)
    stfd 8, FLOAT_ARG_OFFSET + 0x38(1)
    stfd 9, FLOAT_ARG_OFFSET + 0x40(1)
    stfd 10, FLOAT_ARG_OFFSET + 0x48(1)
    stfd 11, FLOAT_ARG_OFFSET + 0x50(1)
    stfd 12, FLOAT_ARG_OFFSET + 0x58(1)
    stfd 13, FLOAT_ARG_OFFSET + 0x60(1)

    std 3, ARGUMENT_REGISTERS_OFFSET(1)
    std 4, ARGUMENT_REGISTERS_OFFSET + 0x08(1)
    std 5, ARGUMENT_REGISTERS_OFFSET + 0x10(1)
    std 6, ARGUMENT_REGISTERS_OFFSET + 0x18(1)
    std 7, ARGUMENT_REGISTERS_OFFSET + 0x20(1)
    std 8, ARGUMENT_REGISTERS_OFFSET + 0x28(1)
    std 9, ARGUMENT_REGISTERS_OFFSET + 0x30(1)
    std 10, ARGUMENT_REGISTERS_OFFSET + 0x38(1)

    addi 3, 1, DISTANCE_FROM_CHILDSP_TO_RETURN_BLOCK
    mr 4, 12
    mr 12, 11
    mtctr 12
    bctrl

.globl ReturnFromUniversalTransitionTailCall
.type ReturnFromUniversalTransitionTailCall,@function
ReturnFromUniversalTransitionTailCall:
    // The resolver returns the final target address in r3. Preserve it while
    // restoring the original call arguments for the tailcall.
    mr 11, 3

    lfd 1, FLOAT_ARG_OFFSET(1)
    lfd 2, FLOAT_ARG_OFFSET + 0x08(1)
    lfd 3, FLOAT_ARG_OFFSET + 0x10(1)
    lfd 4, FLOAT_ARG_OFFSET + 0x18(1)
    lfd 5, FLOAT_ARG_OFFSET + 0x20(1)
    lfd 6, FLOAT_ARG_OFFSET + 0x28(1)
    lfd 7, FLOAT_ARG_OFFSET + 0x30(1)
    lfd 8, FLOAT_ARG_OFFSET + 0x38(1)
    lfd 9, FLOAT_ARG_OFFSET + 0x40(1)
    lfd 10, FLOAT_ARG_OFFSET + 0x48(1)
    lfd 11, FLOAT_ARG_OFFSET + 0x50(1)
    lfd 12, FLOAT_ARG_OFFSET + 0x58(1)
    lfd 13, FLOAT_ARG_OFFSET + 0x60(1)

    ld 3, ARGUMENT_REGISTERS_OFFSET(1)
    ld 4, ARGUMENT_REGISTERS_OFFSET + 0x08(1)
    ld 5, ARGUMENT_REGISTERS_OFFSET + 0x10(1)
    ld 6, ARGUMENT_REGISTERS_OFFSET + 0x18(1)
    ld 7, ARGUMENT_REGISTERS_OFFSET + 0x20(1)
    ld 8, ARGUMENT_REGISTERS_OFFSET + 0x28(1)
    ld 9, ARGUMENT_REGISTERS_OFFSET + 0x30(1)
    ld 10, ARGUMENT_REGISTERS_OFFSET + 0x38(1)

    ld 31, 0(1)
    ld 0, 8(1)
    addi 1, 1, STACK_SIZE
    mtlr 0

    mtctr 11
    bctr

    .size RhpUniversalTransitionTailCall, .-RhpUniversalTransitionTailCall
    .size ReturnFromUniversalTransitionTailCall, .-ReturnFromUniversalTransitionTailCall
