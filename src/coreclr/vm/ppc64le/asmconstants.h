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

#define METHODDESC_REGISTER 12

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

#define SIZEOF__Frame 0x10
ASMCONSTANTS_C_ASSERT(SIZEOF__Frame == sizeof(Frame));

#define SIZEOF__CONTEXT 0x240
ASMCONSTANTS_C_ASSERT(SIZEOF__CONTEXT == sizeof(T_CONTEXT));

#define CONTEXT_Nip 0x210
ASMCONSTANTS_C_ASSERT(CONTEXT_Nip == offsetof(T_CONTEXT, Nip))

#define CONTEXT_R14 0x78
ASMCONSTANTS_C_ASSERT(CONTEXT_R14 == offsetof(T_CONTEXT, R14))

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
