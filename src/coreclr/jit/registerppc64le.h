// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// clang-format off

/*****************************************************************************/
/*****************************************************************************/
#ifndef REGDEF
#error  Must define REGDEF macro before including this file
#endif
#ifndef REGALIAS
#define REGALIAS(alias, realname)
#endif

#define RMASK(x) (1ULL << (x))

/*
REGDEF(name, rnum,       mask, sname) */
REGDEF(R0,      0,     RMASK(0),  "r0" )
REGDEF(R1,      1,     RMASK(1),  "r1" )
REGDEF(R2,      2,     RMASK(2),  "r2" )
REGDEF(R3,      3,     RMASK(3),  "r3" )
REGDEF(R4,      4,     RMASK(4),  "r4" )
REGDEF(R5,      5,     RMASK(5),  "r5" )
REGDEF(R6,      6,     RMASK(6),  "r6" )
REGDEF(R7,      7,     RMASK(7),  "r7" )
REGDEF(R8,      8,     RMASK(8),  "r8" )
REGDEF(R9,      9,     RMASK(9),  "r9" )
REGDEF(R10,    10,    RMASK(10),  "r10")
REGDEF(R11,    11,    RMASK(11),  "r11")
REGDEF(R12,    12,    RMASK(12),  "r12")
REGDEF(R13,    13,    RMASK(13),  "r13")
REGDEF(R14,    14,    RMASK(14),  "r14")
REGDEF(R15,    15,    RMASK(15),  "r15")
REGDEF(R16,    16,    RMASK(16),  "r16")
REGDEF(R17,    17,    RMASK(17),  "r17")
REGDEF(R18,    18,    RMASK(18),  "r18")
REGDEF(R19,    19,    RMASK(19),  "r19")
REGDEF(R20,    20,    RMASK(20),  "r20")
REGDEF(R21,    21,    RMASK(21),  "r21")
REGDEF(R22,    22,    RMASK(22),  "r22")
REGDEF(R23,    23,    RMASK(23),  "r23")
REGDEF(R24,    24,    RMASK(24),  "r24")
REGDEF(R25,    25,    RMASK(25),  "r25")
REGDEF(R26,    26,    RMASK(26),  "r26")
REGDEF(R27,    27,    RMASK(27),  "r27")
REGDEF(R28,    28,    RMASK(28),  "r28")
REGDEF(R29,    29,    RMASK(29),  "r29")
REGDEF(R30,    30,    RMASK(30),  "r30")
REGDEF(R31,    31,    RMASK(31),  "r31")

REGALIAS(SP, R1)
REGALIAS(TOC, R2)
REGALIAS(A0, R3)
REGALIAS(A1, R4)
REGALIAS(A2, R5)
REGALIAS(A3, R6)
REGALIAS(A4, R7)
REGALIAS(A5, R8)
REGALIAS(A6, R9)
REGALIAS(A7, R10)
REGALIAS(T0, R11)
REGALIAS(T1, R12)
REGALIAS(TP, R13)
REGALIAS(FP, R31)

#define FBASE 32
#define FMASK(x) (1ULL << (FBASE+(x)))

/*
REGDEF(name,     rnum,     mask,  sname) */
REGDEF(F0,    0+FBASE, FMASK(0),  "f0" )
REGDEF(F1,    1+FBASE, FMASK(1),  "f1" )
REGDEF(F2,    2+FBASE, FMASK(2),  "f2" )
REGDEF(F3,    3+FBASE, FMASK(3),  "f3" )
REGDEF(F4,    4+FBASE, FMASK(4),  "f4" )
REGDEF(F5,    5+FBASE, FMASK(5),  "f5" )
REGDEF(F6,    6+FBASE, FMASK(6),  "f6" )
REGDEF(F7,    7+FBASE, FMASK(7),  "f7" )
REGDEF(F8,    8+FBASE, FMASK(8),  "f8" )
REGDEF(F9,    9+FBASE, FMASK(9),  "f9" )
REGDEF(F10,  10+FBASE, FMASK(10), "f10")
REGDEF(F11,  11+FBASE, FMASK(11), "f11")
REGDEF(F12,  12+FBASE, FMASK(12), "f12")
REGDEF(F13,  13+FBASE, FMASK(13), "f13")
REGDEF(F14,  14+FBASE, FMASK(14), "f14")
REGDEF(F15,  15+FBASE, FMASK(15), "f15")
REGDEF(F16,  16+FBASE, FMASK(16), "f16")
REGDEF(F17,  17+FBASE, FMASK(17), "f17")
REGDEF(F18,  18+FBASE, FMASK(18), "f18")
REGDEF(F19,  19+FBASE, FMASK(19), "f19")
REGDEF(F20,  20+FBASE, FMASK(20), "f20")
REGDEF(F21,  21+FBASE, FMASK(21), "f21")
REGDEF(F22,  22+FBASE, FMASK(22), "f22")
REGDEF(F23,  23+FBASE, FMASK(23), "f23")
REGDEF(F24,  24+FBASE, FMASK(24), "f24")
REGDEF(F25,  25+FBASE, FMASK(25), "f25")
REGDEF(F26,  26+FBASE, FMASK(26), "f26")
REGDEF(F27,  27+FBASE, FMASK(27), "f27")
REGDEF(F28,  28+FBASE, FMASK(28), "f28")
REGDEF(F29,  29+FBASE, FMASK(29), "f29")
REGDEF(F30,  30+FBASE, FMASK(30), "f30")
REGDEF(F31,  31+FBASE, FMASK(31), "f31")

// The registers with values 64 (NBASE) and above are not real register numbers.
#define NBASE 64

// This must be last.
REGDEF(STK,   0+NBASE, 0x0000,    "STK")

/*****************************************************************************/
#undef  RMASK
#undef  FBASE
#undef  FMASK
#undef  NBASE
#undef  REGDEF
#undef  REGALIAS
/*****************************************************************************/

// clang-format on
