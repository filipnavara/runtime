// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#pragma once

#if !defined(TARGET_POWERPC64)
#error The file should not be included for this platform.
#endif

// clang-format off
#define CORINFO_ARCH_TARGET      CORINFO_ARCH_PPC64LE

#define CPU_LOAD_STORE_ARCH      1
#define CPU_HAS_FP_SUPPORT       1
#define CPU_HAS_BYTE_REGS        0

#ifdef FEATURE_SIMD
#pragma error("SIMD Unimplemented yet PPC64LE")
#endif // FEATURE_SIMD

#define FEATURE_FIXED_OUT_ARGS   1       // Preallocate the outgoing arg area in the prolog.
#define FEATURE_STRUCTPROMOTE    1       // JIT optimization to promote fields of structs into registers.
#define FEATURE_MULTIREG_STRUCT_PROMOTE 1
#define FEATURE_FASTTAILCALL     0       // Tail calls made as epilog+jmp.
#define FEATURE_TAILCALL_OPT     0       // Opportunistic tail calls made as fast tail calls.
#define FEATURE_IMPLICIT_BYREFS       1
#define FEATURE_MULTIREG_ARGS_OR_RET  1
#define FEATURE_MULTIREG_ARGS         1
#define FEATURE_MULTIREG_RET          1
#define MAX_PASS_SINGLEREG_BYTES      8
#define MAX_PASS_MULTIREG_BYTES       16
#define MAX_RET_MULTIREG_BYTES        16
#define MAX_ARG_REG_COUNT             8
#define MAX_RET_REG_COUNT             2
#define MAX_MULTIREG_COUNT            4

#define NOGC_WRITE_BARRIERS      1
#define USER_ARGS_COME_LAST      1
#define TARGET_POINTER_SIZE      8
#define ETW_EBP_FRAMED           1

#define CSE_CONSTS               1
#define EMIT_TRACK_STACK_DEPTH   1
#define EMIT_GENERATE_GCINFO     1

#define REG_FP_FIRST             REG_F0
#define REG_FP_LAST              REG_F31
#define FIRST_FP_ARGREG          REG_F1
#define LAST_FP_ARGREG           REG_F13

#define HAS_FIXED_REGISTER_SET   1
// The emitter also uses idReg1/idReg2 to pack the live callee-saved GC
// register mask on small call descriptors. PPC64LE has 17 integer
// callee-saved registers, so each field must be able to hold half of
// that mask, not just a physical register number.
#define REGNUM_BITS              9
#define REGSIZE_BYTES            8
#define FP_REGSIZE_BYTES         8
#define FPSAVE_REGSIZE_BYTES     8

#define MIN_ARG_AREA_FOR_CALL    (8 * REGSIZE_BYTES)

#define CODE_ALIGN               4
#define STACK_ALIGN              16

#define FIRST_INT_CALLEE_SAVED  REG_R14
#define LAST_INT_CALLEE_SAVED   REG_R30
#define RBM_INT_CALLEE_SAVED    (RBM_R14|RBM_R15|RBM_R16|RBM_R17|RBM_R18|RBM_R19|RBM_R20|RBM_R21|RBM_R22|RBM_R23|RBM_R24|RBM_R25|RBM_R26|RBM_R27|RBM_R28|RBM_R29|RBM_R30)
#define RBM_INT_CALLEE_TRASH    (RBM_R3|RBM_R4|RBM_R5|RBM_R6|RBM_R7|RBM_R8|RBM_R9|RBM_R10|RBM_R11|RBM_R12)
// TODO-PPC64LE: Enable F14-F31 after prolog/epilog support saving callee-saved FPRs.
#define FIRST_FLT_CALLEE_SAVED  REG_NA
#define LAST_FLT_CALLEE_SAVED   REG_NA
#define RBM_FLT_CALLEE_SAVED    RBM_NONE
#define RBM_FLT_CALLEE_TRASH    (RBM_F0|RBM_F1|RBM_F2|RBM_F3|RBM_F4|RBM_F5|RBM_F6|RBM_F7|RBM_F8|RBM_F9|RBM_F10|RBM_F11|RBM_F12|RBM_F13)

#define RBM_CALLEE_SAVED        (RBM_INT_CALLEE_SAVED | RBM_FLT_CALLEE_SAVED)
#define RBM_CALLEE_TRASH        (RBM_INT_CALLEE_TRASH | RBM_FLT_CALLEE_TRASH)

#define REG_DEFAULT_HELPER_CALL_TARGET REG_R12
#define RBM_DEFAULT_HELPER_CALL_TARGET RBM_R12

#define RBM_ALLINT              (RBM_INT_CALLEE_SAVED | RBM_INT_CALLEE_TRASH)
#define RBM_ALLFLOAT            (RBM_FLT_CALLEE_SAVED | RBM_FLT_CALLEE_TRASH)
#define RBM_ALLDOUBLE           RBM_ALLFLOAT

#define REG_VAR_ORDER            REG_R3,REG_R4,REG_R5,REG_R6,REG_R7,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12, \
                                 REG_R14,REG_R15,REG_R16,REG_R17,REG_R18,REG_R19,REG_R20,REG_R21,REG_R22, \
                                 REG_R23,REG_R24,REG_R25,REG_R26,REG_R27,REG_R28,REG_R29,REG_R30

#define REG_VAR_ORDER_FLT        REG_F1,REG_F2,REG_F3,REG_F4,REG_F5,REG_F6,REG_F7,REG_F8,REG_F9,REG_F10,REG_F11,REG_F12,REG_F13,REG_F0

#define CNT_CALLEE_SAVED        (17)
#define CNT_CALLEE_TRASH        (10)
#define CNT_CALLEE_ENREG        (CNT_CALLEE_SAVED)

#define CNT_CALLEE_SAVED_FLOAT  (0)
#define CNT_CALLEE_TRASH_FLOAT  (14)
#define CNT_CALLEE_ENREG_FLOAT  (CNT_CALLEE_SAVED_FLOAT)

#define CNT_CALLEE_SAVED_MASK   (0)
#define CNT_CALLEE_TRASH_MASK   (0)
#define CNT_CALLEE_ENREG_MASK   (CNT_CALLEE_SAVED_MASK)

#define CALLEE_SAVED_REG_MAXSZ    (CNT_CALLEE_SAVED * REGSIZE_BYTES)
#define CALLEE_SAVED_FLOAT_MAXSZ  (CNT_CALLEE_SAVED_FLOAT * FPSAVE_REGSIZE_BYTES)

#define REG_TMP_0                REG_R11

#define RBM_GSCOOKIE_TMP         (RBM_R11 | RBM_R12)

#define REG_SHIFT                REG_NA
#define RBM_SHIFT                RBM_ALLINT

#define REG_SCRATCH              REG_R12
#define REG_SCRATCH_FLT          REG_F0

#define REG_EXCEPTION_OBJECT     REG_R3
#define RBM_EXCEPTION_OBJECT     RBM_R3

#define REG_JUMP_THUNK_PARAM     REG_R12
#define RBM_JUMP_THUNK_PARAM     RBM_R12

#define REG_WRITE_BARRIER_DST          REG_R11
#define RBM_WRITE_BARRIER_DST          RBM_R11

#define REG_WRITE_BARRIER_SRC          REG_R10
#define RBM_WRITE_BARRIER_SRC          RBM_R10

// Byref write barrier source must be distinct from REG_WRITE_BARRIER_SRC.
// RhpByRefAssignRef loads the referenced object into REG_WRITE_BARRIER_SRC
// before tailcalling RhpCheckedAssignRef.
#define REG_WRITE_BARRIER_DST_BYREF    REG_R11
#define RBM_WRITE_BARRIER_DST_BYREF    RBM_R11

#define REG_WRITE_BARRIER_SRC_BYREF    REG_R9
#define RBM_WRITE_BARRIER_SRC_BYREF    RBM_R9

#define RBM_CALLEE_TRASH_NOGC          (RBM_R10|RBM_R11|RBM_R12|RBM_DEFAULT_HELPER_CALL_TARGET)

#define RBM_CALLEE_TRASH_WRITEBARRIER         (RBM_WRITE_BARRIER_DST|RBM_CALLEE_TRASH_NOGC)

// The write barrier helpers post-increment r11 but leave it as a valid byref.
// Keep it in the liveness kill set above, but do not report it as GC-dead.
#define RBM_CALLEE_GCTRASH_WRITEBARRIER       (RBM_CALLEE_TRASH_NOGC & ~RBM_WRITE_BARRIER_DST)
#define RBM_CALLEE_TRASH_WRITEBARRIER_BYREF   (RBM_WRITE_BARRIER_DST_BYREF | RBM_WRITE_BARRIER_SRC_BYREF | RBM_CALLEE_TRASH_NOGC)
#define RBM_CALLEE_GCTRASH_WRITEBARRIER_BYREF (RBM_CALLEE_TRASH_NOGC & ~(RBM_WRITE_BARRIER_DST_BYREF | RBM_WRITE_BARRIER_SRC_BYREF))

#define REG_PINVOKE_COOKIE_PARAM          REG_R11
#define RBM_PINVOKE_COOKIE_PARAM          RBM_R11

#define REG_PINVOKE_TARGET_PARAM          REG_R0
#define RBM_PINVOKE_TARGET_PARAM          RBM_R0

#define REG_SECRET_STUB_PARAM     REG_R11
#define RBM_SECRET_STUB_PARAM     RBM_R11

#define REG_R2R_INDIRECT_PARAM          REG_R11
#define RBM_R2R_INDIRECT_PARAM          RBM_R11

#define REG_INDIRECT_CALL_TARGET_REG    REG_R12

#define REG_FIRST                REG_R0
#define REG_INT_FIRST            REG_R0
#define REG_INT_LAST             REG_R31
#define REG_INT_COUNT            (REG_INT_LAST - REG_INT_FIRST + 1)
#define REG_NEXT(reg)           ((regNumber)((unsigned)(reg) + 1))
#define REG_PREV(reg)           ((regNumber)((unsigned)(reg) - 1))

#define REG_PROFILER_ENTER_ARG_FUNC_ID    REG_R11
#define RBM_PROFILER_ENTER_ARG_FUNC_ID    RBM_R11
#define REG_PROFILER_ENTER_ARG_CALLER_SP  REG_R12
#define RBM_PROFILER_ENTER_ARG_CALLER_SP  RBM_R12
#define REG_PROFILER_LEAVE_ARG_FUNC_ID    REG_PROFILER_ENTER_ARG_FUNC_ID
#define RBM_PROFILER_LEAVE_ARG_FUNC_ID    RBM_PROFILER_ENTER_ARG_FUNC_ID
#define REG_PROFILER_LEAVE_ARG_CALLER_SP  REG_PROFILER_ENTER_ARG_CALLER_SP
#define RBM_PROFILER_LEAVE_ARG_CALLER_SP  RBM_PROFILER_ENTER_ARG_CALLER_SP

#define RBM_PROFILER_ENTER_TRASH     (RBM_CALLEE_TRASH & ~(RBM_ARG_REGS|RBM_FLTARG_REGS|RBM_FP))
#define RBM_PROFILER_LEAVE_TRASH     RBM_PROFILER_ENTER_TRASH
#define RBM_PROFILER_TAILCALL_TRASH  RBM_PROFILER_LEAVE_TRASH

#define REG_INTRET               REG_R3
#define RBM_INTRET               RBM_R3
#define REG_LNGRET               REG_R3
#define RBM_LNGRET               RBM_R3
#define REG_INTRET_1             REG_R4
#define RBM_INTRET_1             RBM_R4

#define REG_FLOATRET             REG_F1
#define RBM_FLOATRET             RBM_F1
#define RBM_DOUBLERET            RBM_F1
#define REG_FLOATRET_1           REG_F2
#define RBM_FLOATRET_1           RBM_F2
#define RBM_DOUBLERET_1          RBM_F2

#define RBM_STOP_FOR_GC_TRASH    RBM_CALLEE_TRASH
#define RBM_INIT_PINVOKE_FRAME_TRASH  RBM_CALLEE_TRASH

#define RBM_VALIDATE_INDIRECT_CALL_TRASH (RBM_INT_CALLEE_TRASH & ~(RBM_R3 | RBM_R4 | RBM_R5 | RBM_R6 | RBM_R7 | RBM_R8 | RBM_R9 | RBM_R10 | RBM_R11))
#define REG_VALIDATE_INDIRECT_CALL_ADDR REG_R11
#define REG_DISPATCH_INDIRECT_CALL_ADDR REG_R12

#define REG_ASYNC_CONTINUATION_RET REG_R5
#define RBM_ASYNC_CONTINUATION_RET RBM_R5

#define REG_FPBASE               REG_FP
#define RBM_FPBASE               RBM_FP
#define STR_FPBASE               "r31"
#define REG_SPBASE               REG_SP
#define RBM_SPBASE               RBM_SP
#define STR_SPBASE               "r1"

#define FIRST_ARG_STACK_OFFS    (12 * REGSIZE_BYTES)

#define MAX_REG_ARG              8
#define MAX_FLOAT_REG_ARG        13

#define REG_ARG_FIRST            REG_R3
#define REG_ARG_LAST             REG_R10
#define REG_ARG_FP_FIRST         REG_F1
#define REG_ARG_FP_LAST          REG_F13
#define INIT_ARG_STACK_SLOT      0

#define REG_FLTARG_0             REG_F1
#define REG_FLTARG_1             REG_F2
#define REG_FLTARG_2             REG_F3
#define REG_FLTARG_3             REG_F4
#define REG_FLTARG_4             REG_F5
#define REG_FLTARG_5             REG_F6
#define REG_FLTARG_6             REG_F7
#define REG_FLTARG_7             REG_F8
#define REG_FLTARG_8             REG_F9
#define REG_FLTARG_9             REG_F10
#define REG_FLTARG_10            REG_F11
#define REG_FLTARG_11            REG_F12
#define REG_FLTARG_12            REG_F13

#define REG_ARG_0                REG_R3
#define REG_ARG_1                REG_R4
#define REG_ARG_2                REG_R5
#define REG_ARG_3                REG_R6
#define REG_ARG_4                REG_R7
#define REG_ARG_5                REG_R8
#define REG_ARG_6                REG_R9
#define REG_ARG_7                REG_R10

  extern const regNumber intArgRegs [MAX_REG_ARG];
  extern const regMaskTP intArgMasks[MAX_REG_ARG];

#define RBM_ARG_0                RBM_R3
#define RBM_ARG_1                RBM_R4
#define RBM_ARG_2                RBM_R5
#define RBM_ARG_3                RBM_R6
#define RBM_ARG_4                RBM_R7
#define RBM_ARG_5                RBM_R8
#define RBM_ARG_6                RBM_R9
#define RBM_ARG_7                RBM_R10

#define RBM_ARG_REGS            (RBM_R3|RBM_R4|RBM_R5|RBM_R6|RBM_R7|RBM_R8|RBM_R9|RBM_R10)
#define RBM_FLTARG_REGS         (RBM_F1|RBM_F2|RBM_F3|RBM_F4|RBM_F5|RBM_F6|RBM_F7|RBM_F8|RBM_F9|RBM_F10|RBM_F11|RBM_F12|RBM_F13)

  extern const regNumber fltArgRegs [MAX_FLOAT_REG_ARG];
  extern const regMaskTP fltArgMasks[MAX_FLOAT_REG_ARG];

#define J_DIST_SMALL_MAX_NEG  (-(1 << 25))
#define J_DIST_SMALL_MAX_POS  (+(1 << 25) - 4)

#define B_DIST_SMALL_MAX_NEG  (-(1 << 15))
#define B_DIST_SMALL_MAX_POS  (+(1 << 15) - 4)

#define STACK_PROBE_BOUNDARY_THRESHOLD_BYTES 0

// clang-format on
