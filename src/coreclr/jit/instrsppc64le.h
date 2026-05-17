// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*****************************************************************************
 *  PPC64LE instructions for JIT compiler
 *
 *          id          -- the enum name for the instruction
 *          nm          -- textual name (for assembly display)
 *          ld/st/cmp   -- load/store/compare instruction
 *          encode      -- primary encoding bits
 *
 ******************************************************************************/

#if !defined(TARGET_POWERPC64)
#error Unexpected target type
#endif

#ifndef INST
#error INST must be defined before including this file.
#endif

// clang-format off

INST(invalid,       "INVALID",        0,    BAD_CODE)
INST(nop,           "nop",            0,    0x60000000)
INST(trap,          "trap",           0,    0x7FE00008)

INST(add,           "add",            0,    0x7C000214)
INST(addi,          "addi",           0,    0x38000000)
INST(addis,         "addis",          0,    0x3C000000)
INST(mr,            "mr",             0,    0x7C000378)
INST(mov,           "mr",             0,    0x7C000378)
INST(ori,           "ori",            0,    0x60000000)
INST(oris,          "oris",           0,    0x64000000)

INST(ld,            "ld",             LD,   0xE8000000)
INST(lwz,           "lwz",            LD,   0x80000000)
INST(lhz,           "lhz",            LD,   0xA0000000)
INST(lbz,           "lbz",            LD,   0x88000000)
INST(std,           "std",            ST,   0xF8000000)
INST(stw,           "stw",            ST,   0x90000000)
INST(sth,           "sth",            ST,   0xB0000000)
INST(stb,           "stb",            ST,   0x98000000)

INST(cmpd,          "cmpd",           0,    0x7C000000)
INST(cmpw,          "cmpw",           0,    0x7C000000)
INST(cmp,           "cmp",            0,    0x7C000000)
INST(cmpld,         "cmpld",          0,    0x7C000040)
INST(cmplw,         "cmplw",          0,    0x7C000040)
INST(cmpl,          "cmpl",           0,    0x7C000040)

INST(b,             "b",              0,    0x48000000)
INST(bl,            "bl",             0,    0x48000001)
INST(bc,            "bc",             0,    0x40000000)
INST(blt,           "blt",            0,    0x41800000)
INST(bge,           "bge",            0,    0x40800000)
INST(bgt,           "bgt",            0,    0x41810000)
INST(ble,           "ble",            0,    0x40810000)
INST(beq,           "beq",            0,    0x41820000)
INST(bne,           "bne",            0,    0x40820000)
INST(bclr,          "bclr",           0,    0x4C000020)
INST(blr,           "blr",            0,    0x4E800020)

// clang-format on
/*****************************************************************************/
#undef INST
/*****************************************************************************/
