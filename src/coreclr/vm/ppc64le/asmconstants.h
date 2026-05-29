// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "../../inc/switches.h"

#ifndef ASMCONSTANTS_C_ASSERT
#define ASMCONSTANTS_C_ASSERT(cond)
#endif

#ifndef ASMCONSTANTS_RUNTIME_ASSERT
#define ASMCONSTANTS_RUNTIME_ASSERT(cond)
#endif

#define FRAMETYPE_InlinedCallFrame 0x1
ASMCONSTANTS_C_ASSERT(FRAMETYPE_InlinedCallFrame == (int)FrameIdentifier::InlinedCallFrame)

#define DynamicHelperFrameFlags_Default    0
#define DynamicHelperFrameFlags_ObjectArg  1
#define DynamicHelperFrameFlags_ObjectArg2 2

#define Thread__m_fPreemptiveGCDisabled 0x04
#define Thread__m_pFrame                0x08
ASMCONSTANTS_C_ASSERT(Thread__m_fPreemptiveGCDisabled == offsetof(Thread, m_fPreemptiveGCDisabled));
ASMCONSTANTS_C_ASSERT(Thread__m_pFrame == offsetof(Thread, m_pFrame));

#define Thread_m_pFrame Thread__m_pFrame
#define Thread_m_fPreemptiveGCDisabled Thread__m_fPreemptiveGCDisabled

#define OFFSETOF__RuntimeThreadLocals__ee_alloc_context 0
ASMCONSTANTS_C_ASSERT(OFFSETOF__RuntimeThreadLocals__ee_alloc_context == offsetof(RuntimeThreadLocals, alloc_context));

#define OFFSETOF__ThreadLocalInfo__m_pThread 0
ASMCONSTANTS_C_ASSERT(OFFSETOF__ThreadLocalInfo__m_pThread == offsetof(ThreadLocalInfo, m_pThread));

#define OFFSETOF__DynamicStaticsInfo__m_pGCStatics 0
ASMCONSTANTS_C_ASSERT(OFFSETOF__DynamicStaticsInfo__m_pGCStatics == offsetof(DynamicStaticsInfo, m_pGCStatics));

#define OFFSETOF__DynamicStaticsInfo__m_pNonGCStatics 0x8
ASMCONSTANTS_C_ASSERT(OFFSETOF__DynamicStaticsInfo__m_pNonGCStatics ==
                      offsetof(DynamicStaticsInfo, m_pNonGCStatics));

#define OFFSETOF__DynamicStaticsInfo__m_pMethodTable 0x10
ASMCONSTANTS_C_ASSERT(OFFSETOF__DynamicStaticsInfo__m_pMethodTable == offsetof(DynamicStaticsInfo, m_pMethodTable));

#define OFFSETOF__ee_alloc_context__alloc_ptr 0x8
ASMCONSTANTS_C_ASSERT(OFFSETOF__ee_alloc_context__alloc_ptr == offsetof(ee_alloc_context, m_GCAllocContext) +
                                                               offsetof(gc_alloc_context, alloc_ptr));

#define OFFSETOF__ee_alloc_context__combined_limit 0x0
ASMCONSTANTS_C_ASSERT(OFFSETOF__ee_alloc_context__combined_limit == offsetof(ee_alloc_context, m_CombinedLimit));

#define SIZEOF__ArgumentRegisters 0x40
ASMCONSTANTS_C_ASSERT(SIZEOF__ArgumentRegisters == sizeof(ArgumentRegisters))

#define SIZEOF__FloatArgumentRegisters 0x68
ASMCONSTANTS_C_ASSERT(SIZEOF__FloatArgumentRegisters == sizeof(FloatArgumentRegisters))

#define ASM_ENREGISTERED_RETURNTYPE_MAXSIZE 0x10
ASMCONSTANTS_C_ASSERT(ASM_ENREGISTERED_RETURNTYPE_MAXSIZE == ENREGISTERED_RETURNTYPE_MAXSIZE)

#define CallDescrData__pSrc                     0x00
#define CallDescrData__numStackSlots            0x08
#define CallDescrData__pArgumentRegisters       0x10
#define CallDescrData__pFloatArgumentRegisters  0x18
#define CallDescrData__fpReturnSize             0x20
#define CallDescrData__pTarget                  0x28
#define CallDescrData__returnValue              0x30

ASMCONSTANTS_C_ASSERT(CallDescrData__pSrc                 == offsetof(CallDescrData, pSrc))
ASMCONSTANTS_C_ASSERT(CallDescrData__numStackSlots        == offsetof(CallDescrData, numStackSlots))
ASMCONSTANTS_C_ASSERT(CallDescrData__pArgumentRegisters   == offsetof(CallDescrData, pArgumentRegisters))
ASMCONSTANTS_C_ASSERT(CallDescrData__pFloatArgumentRegisters == offsetof(CallDescrData, pFloatArgumentRegisters))
ASMCONSTANTS_C_ASSERT(CallDescrData__fpReturnSize         == offsetof(CallDescrData, fpReturnSize))
ASMCONSTANTS_C_ASSERT(CallDescrData__pTarget              == offsetof(CallDescrData, pTarget))
ASMCONSTANTS_C_ASSERT(CallDescrData__returnValue          == offsetof(CallDescrData, returnValue))

#define FpStruct__BothFloat 0b10
ASMCONSTANTS_C_ASSERT(FpStruct__BothFloat == (int)FpStruct::BothFloat)

#define FpStruct__HomogeneousAggregate 0x100
ASMCONSTANTS_C_ASSERT(FpStruct__HomogeneousAggregate == (int)FpStruct::HomogeneousAggregate)

#define FpStruct__SizeShift1stMask 0x30
ASMCONSTANTS_C_ASSERT(FpStruct__SizeShift1stMask == (int)FpStruct::SizeShift1stMask)

#define FpStruct__HomogeneousAggregateCountMask 0x1E00
ASMCONSTANTS_C_ASSERT(FpStruct__HomogeneousAggregateCountMask == (int)FpStruct::HomogeneousAggregateCountMask)

#define FpStruct__PosHomogeneousAggregateCount 9
ASMCONSTANTS_C_ASSERT(FpStruct__PosHomogeneousAggregateCount == (int)FpStruct::PosHomogeneousAggregateCount)

#define PROFILE_ENTER    1
#define PROFILE_LEAVE    2
#define PROFILE_TAILCALL 4

#ifdef PROFILING_SUPPORTED
#define SIZEOF__PROFILE_PLATFORM_SPECIFIC_DATA 0x190
ASMCONSTANTS_C_ASSERT(SIZEOF__PROFILE_PLATFORM_SPECIFIC_DATA == (sizeof(PROFILE_PLATFORM_SPECIFIC_DATA) + 8))
ASMCONSTANTS_C_ASSERT((SIZEOF__PROFILE_PLATFORM_SPECIFIC_DATA & 0xf) == 0)

#define ASMCONSTANTS_C_ASSERT_OFFSET(type, field) \
    ASMCONSTANTS_C_ASSERT(type##__##field == offsetof(type, field))

#define PROFILE_PLATFORM_SPECIFIC_DATA__Fp                     0
#define PROFILE_PLATFORM_SPECIFIC_DATA__Pc                     8
#define PROFILE_PLATFORM_SPECIFIC_DATA__argumentRegisters      16
#define PROFILE_PLATFORM_SPECIFIC_DATA__functionId             80
#define PROFILE_PLATFORM_SPECIFIC_DATA__floatArgumentRegisters 88
#define PROFILE_PLATFORM_SPECIFIC_DATA__probeSp                192
#define PROFILE_PLATFORM_SPECIFIC_DATA__profiledSp             200
#define PROFILE_PLATFORM_SPECIFIC_DATA__hiddenArg              208
#define PROFILE_PLATFORM_SPECIFIC_DATA__flags                  216
#define PROFILE_PLATFORM_SPECIFIC_DATA__buffer                 224

ASMCONSTANTS_C_ASSERT_OFFSET(PROFILE_PLATFORM_SPECIFIC_DATA, Fp)
ASMCONSTANTS_C_ASSERT_OFFSET(PROFILE_PLATFORM_SPECIFIC_DATA, Pc)
ASMCONSTANTS_C_ASSERT_OFFSET(PROFILE_PLATFORM_SPECIFIC_DATA, argumentRegisters)
ASMCONSTANTS_C_ASSERT_OFFSET(PROFILE_PLATFORM_SPECIFIC_DATA, functionId)
ASMCONSTANTS_C_ASSERT_OFFSET(PROFILE_PLATFORM_SPECIFIC_DATA, floatArgumentRegisters)
ASMCONSTANTS_C_ASSERT_OFFSET(PROFILE_PLATFORM_SPECIFIC_DATA, probeSp)
ASMCONSTANTS_C_ASSERT_OFFSET(PROFILE_PLATFORM_SPECIFIC_DATA, profiledSp)
ASMCONSTANTS_C_ASSERT_OFFSET(PROFILE_PLATFORM_SPECIFIC_DATA, hiddenArg)
ASMCONSTANTS_C_ASSERT_OFFSET(PROFILE_PLATFORM_SPECIFIC_DATA, flags)
ASMCONSTANTS_C_ASSERT_OFFSET(PROFILE_PLATFORM_SPECIFIC_DATA, buffer)
#undef ASMCONSTANTS_C_ASSERT_OFFSET
#endif // PROFILING_SUPPORTED

#define METHODDESC_REGISTER 11

#define StubPrecodeData__SecretParam 0x00
#define StubPrecodeData__Target      0x08
ASMCONSTANTS_C_ASSERT(StubPrecodeData__SecretParam == offsetof(StubPrecodeData, SecretParam))
ASMCONSTANTS_C_ASSERT(StubPrecodeData__Target == offsetof(StubPrecodeData, Target))

#define FixupPrecodeData__Target 0x00
#define FixupPrecodeData__MethodDesc 0x08
#define FixupPrecodeData__PrecodeFixupThunk 0x10
ASMCONSTANTS_C_ASSERT(FixupPrecodeData__Target == offsetof(FixupPrecodeData, Target))
ASMCONSTANTS_C_ASSERT(FixupPrecodeData__MethodDesc == offsetof(FixupPrecodeData, MethodDesc))
ASMCONSTANTS_C_ASSERT(FixupPrecodeData__PrecodeFixupThunk == offsetof(FixupPrecodeData, PrecodeFixupThunk))

#define MAX_STRING_LENGTH 0x3FFFFFDF
ASMCONSTANTS_C_ASSERT(MAX_STRING_LENGTH == CORINFO_String_MaxLength);

#define STRING_BASE_SIZE 0x16
ASMCONSTANTS_C_ASSERT(STRING_BASE_SIZE == OBJECT_BASESIZE + sizeof(DWORD) + sizeof(WCHAR));

#define SZARRAY_BASE_SIZE 0x18
ASMCONSTANTS_C_ASSERT(SZARRAY_BASE_SIZE == OBJECT_BASESIZE + sizeof(DWORD) + sizeof(DWORD));

#define OFFSETOF__MethodTable__m_usComponentSize 0
ASMCONSTANTS_C_ASSERT(OFFSETOF__MethodTable__m_usComponentSize == offsetof(MethodTable, m_dwFlags));

#define OFFSETOF__MethodTable__m_uBaseSize 0x04
ASMCONSTANTS_C_ASSERT(OFFSETOF__MethodTable__m_uBaseSize == offsetof(MethodTable, m_BaseSize));

#define OFFSETOF__Object__m_pEEType 0
ASMCONSTANTS_C_ASSERT(OFFSETOF__Object__m_pEEType == offsetof(Object, m_pMethTab));

#define OFFSETOF__Array__m_Length 0x8
ASMCONSTANTS_C_ASSERT(OFFSETOF__Array__m_Length == offsetof(ArrayBase, m_NumComponents));

#define SIZEOF__Frame 0x10
ASMCONSTANTS_C_ASSERT(SIZEOF__Frame == sizeof(Frame));

#define Frame__m_Next 0x08
ASMCONSTANTS_C_ASSERT(Frame__m_Next == offsetof(Frame, m_Next))

#define InlinedCallFrame__m_Datum 0x10
ASMCONSTANTS_C_ASSERT(InlinedCallFrame__m_Datum == offsetof(InlinedCallFrame, m_Datum))

#define InlinedCallFrame__m_pCallSiteSP 0x18
ASMCONSTANTS_C_ASSERT(InlinedCallFrame__m_pCallSiteSP == offsetof(InlinedCallFrame, m_pCallSiteSP))

#define InlinedCallFrame__m_pCallerReturnAddress 0x20
ASMCONSTANTS_C_ASSERT(InlinedCallFrame__m_pCallerReturnAddress == offsetof(InlinedCallFrame, m_pCallerReturnAddress))

#define InlinedCallFrame__m_pCalleeSavedFP 0x28
ASMCONSTANTS_C_ASSERT(InlinedCallFrame__m_pCalleeSavedFP == offsetof(InlinedCallFrame, m_pCalleeSavedFP))

#define InlinedCallFrame__m_pThread 0x30
ASMCONSTANTS_C_ASSERT(InlinedCallFrame__m_pThread == offsetof(InlinedCallFrame, m_pThread))

#define VASigCookie__pPInvokeILStub 0x8
ASMCONSTANTS_C_ASSERT(VASigCookie__pPInvokeILStub == offsetof(VASigCookie, pPInvokeILStub))

#define HijackArgs__R31 0x00
#define HijackArgs__Link 0x08
#define HijackArgs__R14 0x10
#define HijackArgs__R15 0x18
#define HijackArgs__R16 0x20
#define HijackArgs__R17 0x28
#define HijackArgs__R18 0x30
#define HijackArgs__R19 0x38
#define HijackArgs__R20 0x40
#define HijackArgs__R21 0x48
#define HijackArgs__R22 0x50
#define HijackArgs__R23 0x58
#define HijackArgs__R24 0x60
#define HijackArgs__R25 0x68
#define HijackArgs__R26 0x70
#define HijackArgs__R27 0x78
#define HijackArgs__R28 0x80
#define HijackArgs__R29 0x88
#define HijackArgs__R30 0x90
#define HijackArgs__R3  0x98
#define HijackArgs__R4  0xA0
#define HijackArgs__R5  0xA8
#define HijackArgs__F1  0xB0
#define HijackArgs__F2  0xB8
#define SIZEOF__HijackArgs 0xC0

ASMCONSTANTS_C_ASSERT(HijackArgs__R31 == offsetof(HijackArgs, R31))
ASMCONSTANTS_C_ASSERT(HijackArgs__Link == offsetof(HijackArgs, Link))
ASMCONSTANTS_C_ASSERT(HijackArgs__R14 == offsetof(HijackArgs, R14))
ASMCONSTANTS_C_ASSERT(HijackArgs__R30 == offsetof(HijackArgs, R30))
ASMCONSTANTS_C_ASSERT(HijackArgs__R3 == offsetof(HijackArgs, R3))
ASMCONSTANTS_C_ASSERT(HijackArgs__R4 == offsetof(HijackArgs, R4))
ASMCONSTANTS_C_ASSERT(HijackArgs__R5 == offsetof(HijackArgs, R5))
ASMCONSTANTS_C_ASSERT(HijackArgs__F1 == offsetof(HijackArgs, F1))
ASMCONSTANTS_C_ASSERT(HijackArgs__F2 == offsetof(HijackArgs, F2))
ASMCONSTANTS_C_ASSERT(SIZEOF__HijackArgs == sizeof(HijackArgs))

#define SIZEOF__CONTEXT 0x240
ASMCONSTANTS_C_ASSERT(SIZEOF__CONTEXT == sizeof(T_CONTEXT));

#define CONTEXT_Nip 0x210
ASMCONSTANTS_C_ASSERT(CONTEXT_Nip == offsetof(T_CONTEXT, Nip))

#define CONTEXT_R14 0x78
ASMCONSTANTS_C_ASSERT(CONTEXT_R14 == offsetof(T_CONTEXT, R14))

#define CONTEXT_R15 0x80
ASMCONSTANTS_C_ASSERT(CONTEXT_R15 == offsetof(T_CONTEXT, R15))

#define CONTEXT_R16 0x88
ASMCONSTANTS_C_ASSERT(CONTEXT_R16 == offsetof(T_CONTEXT, R16))

#define CONTEXT_R17 0x90
ASMCONSTANTS_C_ASSERT(CONTEXT_R17 == offsetof(T_CONTEXT, R17))

#define CONTEXT_R18 0x98
ASMCONSTANTS_C_ASSERT(CONTEXT_R18 == offsetof(T_CONTEXT, R18))

#define CONTEXT_R19 0xA0
ASMCONSTANTS_C_ASSERT(CONTEXT_R19 == offsetof(T_CONTEXT, R19))

#define CONTEXT_R20 0xA8
ASMCONSTANTS_C_ASSERT(CONTEXT_R20 == offsetof(T_CONTEXT, R20))

#define CONTEXT_R21 0xB0
ASMCONSTANTS_C_ASSERT(CONTEXT_R21 == offsetof(T_CONTEXT, R21))

#define CONTEXT_R22 0xB8
ASMCONSTANTS_C_ASSERT(CONTEXT_R22 == offsetof(T_CONTEXT, R22))

#define CONTEXT_R23 0xC0
ASMCONSTANTS_C_ASSERT(CONTEXT_R23 == offsetof(T_CONTEXT, R23))

#define CONTEXT_R24 0xC8
ASMCONSTANTS_C_ASSERT(CONTEXT_R24 == offsetof(T_CONTEXT, R24))

#define CONTEXT_R25 0xD0
ASMCONSTANTS_C_ASSERT(CONTEXT_R25 == offsetof(T_CONTEXT, R25))

#define CONTEXT_R26 0xD8
ASMCONSTANTS_C_ASSERT(CONTEXT_R26 == offsetof(T_CONTEXT, R26))

#define CONTEXT_R27 0xE0
ASMCONSTANTS_C_ASSERT(CONTEXT_R27 == offsetof(T_CONTEXT, R27))

#define CONTEXT_R28 0xE8
ASMCONSTANTS_C_ASSERT(CONTEXT_R28 == offsetof(T_CONTEXT, R28))

#define CONTEXT_R29 0xF0
ASMCONSTANTS_C_ASSERT(CONTEXT_R29 == offsetof(T_CONTEXT, R29))

#define CONTEXT_R30 0xF8
ASMCONSTANTS_C_ASSERT(CONTEXT_R30 == offsetof(T_CONTEXT, R30))

#define CONTEXT_R31 0x100
ASMCONSTANTS_C_ASSERT(CONTEXT_R31 == offsetof(T_CONTEXT, R31))

#define CONTEXT_Link 0x228
ASMCONSTANTS_C_ASSERT(CONTEXT_Link == offsetof(T_CONTEXT, Link))

#define SIZEOF__FixupPrecode 88
#define MethodDesc_ALIGNMENT_SHIFT 3
ASMCONSTANTS_C_ASSERT(SIZEOF__FixupPrecode == sizeof(FixupPrecode));
ASMCONSTANTS_C_ASSERT(MethodDesc_ALIGNMENT_SHIFT == MethodDesc::ALIGNMENT_SHIFT);

#define SIZEOF__TransitionBlock 0xE0
ASMCONSTANTS_C_ASSERT(SIZEOF__TransitionBlock == sizeof(TransitionBlock))

#define TransitionBlock__r31 0x00
#define TransitionBlock__m_ReturnAddress 0x08
#define TransitionBlock__r14 0x10
#define TransitionBlock__r15 0x18
#define TransitionBlock__r16 0x20
#define TransitionBlock__r17 0x28
#define TransitionBlock__r18 0x30
#define TransitionBlock__r19 0x38
#define TransitionBlock__r20 0x40
#define TransitionBlock__r21 0x48
#define TransitionBlock__r22 0x50
#define TransitionBlock__r23 0x58
#define TransitionBlock__r24 0x60
#define TransitionBlock__r25 0x68
#define TransitionBlock__r26 0x70
#define TransitionBlock__r27 0x78
#define TransitionBlock__r28 0x80
#define TransitionBlock__r29 0x88
#define TransitionBlock__r30 0x90
#define TransitionBlock__m_argumentRegisters 0xA0

ASMCONSTANTS_C_ASSERT(TransitionBlock__r31 == offsetof(TransitionBlock, r31))
ASMCONSTANTS_C_ASSERT(TransitionBlock__m_ReturnAddress == offsetof(TransitionBlock, m_ReturnAddress))
ASMCONSTANTS_C_ASSERT(TransitionBlock__r14 == offsetof(TransitionBlock, r14))
ASMCONSTANTS_C_ASSERT(TransitionBlock__r30 == offsetof(TransitionBlock, r30))
ASMCONSTANTS_C_ASSERT(TransitionBlock__m_argumentRegisters == offsetof(TransitionBlock, m_argumentRegisters))

#undef ASMCONSTANTS_RUNTIME_ASSERT
#undef ASMCONSTANTS_C_ASSERT
