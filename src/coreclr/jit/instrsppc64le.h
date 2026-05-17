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
INST(sync,          "sync",           0,    0x7C0004AC)

INST(mflr,          "mflr",           0,    0x7C0802A6)
INST(mtlr,          "mtlr",           0,    0x7C0803A6)
INST(mtctr,         "mtctr",          0,    0x7C0903A6)

INST(add,           "add",            0,    0x7C000214)
INST(subf,          "subf",           0,    0x7C000050)
INST(mulhw,         "mulhw",          0,    0x7C000096)
INST(mulhwu,        "mulhwu",         0,    0x7C000016)
INST(mullw,         "mullw",          0,    0x7C0001D6)
INST(mulhd,         "mulhd",          0,    0x7C000092)
INST(mulhdu,        "mulhdu",         0,    0x7C000012)
INST(mulld,         "mulld",          0,    0x7C0001D2)
INST(divw,          "divw",           0,    0x7C0003D6)
INST(divd,          "divd",           0,    0x7C0003D2)
INST(divwu,         "divwu",          0,    0x7C000396)
INST(divdu,         "divdu",          0,    0x7C000392)
INST(slw,           "slw",            0,    0x7C000030)
INST(sld,           "sld",            0,    0x7C000036)
INST(sraw,          "sraw",           0,    0x7C000630)
INST(srad,          "srad",           0,    0x7C000634)
INST(srw,           "srw",            0,    0x7C000430)
INST(srd,           "srd",            0,    0x7C000436)
INST(sldi,          "sldi",           0,    0x78000004)
INST(and,           "and",            0,    0x7C000038)
INST(andc,          "andc",           0,    0x7C000078)
INST(or,            "or",             0,    0x7C000378)
INST(orc,           "orc",            0,    0x7C000338)
INST(xor,           "xor",            0,    0x7C000278)
INST(xori,          "xori",           0,    0x68000000)
INST(eqv,           "eqv",            0,    0x7C000238)
INST(neg,           "neg",            0,    0x7C0000D0)
INST(not,           "not",            0,    0x7C0000F8)
INST(extsb,         "extsb",          0,    0x7C000774)
INST(extsh,         "extsh",          0,    0x7C000734)
INST(extsw,         "extsw",          0,    0x7C0007B4)
INST(fmr,           "fmr",            0,    0xFC000090)
INST(fneg,          "fneg",           0,    0xFC000050)
INST(frsp,          "frsp",           0,    0xFC000018)
INST(fctiwz,        "fctiwz",         0,    0xFC00001E)
INST(fctidz,        "fctidz",         0,    0xFC00065E)
INST(fctiduz,       "fctiduz",        0,    0xFC00075E)
INST(fcfid,         "fcfid",          0,    0xFC00069C)
INST(fcfids,        "fcfids",         0,    0xEC00069C)
INST(fcfidu,        "fcfidu",         0,    0xFC00079C)
INST(fcfidus,       "fcfidus",        0,    0xEC00079C)
INST(mffgpr,        "mffgpr",         0,    0x7C0004BE)
INST(mftgpr,        "mftgpr",         0,    0x7C0005BE)
INST(fadd,          "fadd",           0,    0xFC00002A)
INST(fadds,         "fadds",          0,    0xEC00002A)
INST(fsub,          "fsub",           0,    0xFC000028)
INST(fsubs,         "fsubs",          0,    0xEC000028)
INST(fmul,          "fmul",           0,    0xFC000032)
INST(fmuls,         "fmuls",          0,    0xEC000032)
INST(fdiv,          "fdiv",           0,    0xFC000024)
INST(fdivs,         "fdivs",          0,    0xEC000024)
INST(clrldi,        "clrldi",         0,    0x78000000)
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
INST(lfs,           "lfs",            LD,   0xC0000000)
INST(lfd,           "lfd",            LD,   0xC8000000)
INST(std,           "std",            ST,   0xF8000000)
INST(stw,           "stw",            ST,   0x90000000)
INST(sth,           "sth",            ST,   0xB0000000)
INST(stb,           "stb",            ST,   0x98000000)
INST(stfs,          "stfs",           ST,   0xD0000000)
INST(stfd,          "stfd",           ST,   0xD8000000)

INST(cmpd,          "cmpd",           0,    0x7C000000)
INST(cmpw,          "cmpw",           0,    0x7C000000)
INST(cmp,           "cmp",            0,    0x7C000000)
INST(cmpld,         "cmpld",          0,    0x7C000040)
INST(cmplw,         "cmplw",          0,    0x7C000040)
INST(cmpl,          "cmpl",           0,    0x7C000040)
INST(fcmpu,         "fcmpu",          0,    0xFC000000)

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
INST(bctrl,         "bctrl",          0,    0x4E800421)

// clang-format on
/*****************************************************************************/
#undef INST
/*****************************************************************************/
