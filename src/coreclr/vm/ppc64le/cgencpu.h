// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef TARGET_POWERPC64
#error Should only include "cgencpu.h" for PPC64LE builds
#endif

#ifndef __cgencpu_h__
#define __cgencpu_h__

#define INSTRFMT_K64
#include <stublink.h>

#ifndef TARGET_UNIX
#define USE_REDIRECT_FOR_GCSTRESS
#endif // TARGET_UNIX

#define ENUM_CALLEE_SAVED_REGISTERS() \
    CALLEE_SAVED_REGISTER(R31)         \
    CALLEE_SAVED_REGISTER(R14)         \
    CALLEE_SAVED_REGISTER(R15)         \
    CALLEE_SAVED_REGISTER(R16)         \
    CALLEE_SAVED_REGISTER(R17)         \
    CALLEE_SAVED_REGISTER(R18)         \
    CALLEE_SAVED_REGISTER(R19)         \
    CALLEE_SAVED_REGISTER(R20)         \
    CALLEE_SAVED_REGISTER(R21)         \
    CALLEE_SAVED_REGISTER(R22)         \
    CALLEE_SAVED_REGISTER(R23)         \
    CALLEE_SAVED_REGISTER(R24)         \
    CALLEE_SAVED_REGISTER(R25)         \
    CALLEE_SAVED_REGISTER(R26)         \
    CALLEE_SAVED_REGISTER(R27)         \
    CALLEE_SAVED_REGISTER(R28)         \
    CALLEE_SAVED_REGISTER(R29)         \
    CALLEE_SAVED_REGISTER(R30)

#define ENUM_FP_CALLEE_SAVED_REGISTERS() \
    CALLEE_SAVED_REGISTER(F14)           \
    CALLEE_SAVED_REGISTER(F15)           \
    CALLEE_SAVED_REGISTER(F16)           \
    CALLEE_SAVED_REGISTER(F17)           \
    CALLEE_SAVED_REGISTER(F18)           \
    CALLEE_SAVED_REGISTER(F19)           \
    CALLEE_SAVED_REGISTER(F20)           \
    CALLEE_SAVED_REGISTER(F21)           \
    CALLEE_SAVED_REGISTER(F22)           \
    CALLEE_SAVED_REGISTER(F23)           \
    CALLEE_SAVED_REGISTER(F24)           \
    CALLEE_SAVED_REGISTER(F25)           \
    CALLEE_SAVED_REGISTER(F26)           \
    CALLEE_SAVED_REGISTER(F27)           \
    CALLEE_SAVED_REGISTER(F28)           \
    CALLEE_SAVED_REGISTER(F29)           \
    CALLEE_SAVED_REGISTER(F30)           \
    CALLEE_SAVED_REGISTER(F31)

class ComCallMethodDesc;

extern PCODE GetPreStubEntryPoint();

#define STACK_ALIGN_SIZE 16

#define JUMP_ALLOCATE_SIZE              32
#define BACK_TO_BACK_JUMP_ALLOCATE_SIZE 40

#define HAS_PINVOKE_IMPORT_PRECODE 1
#define HAS_FIXUP_PRECODE          1
#define HAS_THISPTR_RETBUF_PRECODE 1

#define CODE_SIZE_ALIGN 8
#define CACHE_LINE_SIZE 128
#define LOG2SLOT        LOG2_PTRSIZE

#define ENREGISTERED_RETURNTYPE_MAXSIZE         16
#define ENREGISTERED_RETURNTYPE_INTEGER_MAXSIZE 16
#define ENREGISTERED_PARAMTYPE_MAXSIZE          16

#define CALLDESCR_ARGREGS   1
#define CALLDESCR_FPARGREGS 1

#define FLOAT_REGISTER_SIZE 8

#define STACKWALK_CONTROLPC_ADJUST_OFFSET 4

inline unsigned StackElemSize(unsigned parmSize, bool isValueType, bool isFloatHfa)
{
    const unsigned stackSlotSize = 8;
    return ALIGN_UP(parmSize, stackSlotSize);
}

#define JIT_GetDynamicGCStaticBase    JIT_GetDynamicGCStaticBase_SingleAppDomain
#define JIT_GetDynamicNonGCStaticBase JIT_GetDynamicNonGCStaticBase_SingleAppDomain

typedef DPTR(struct CalleeSavedRegisters) PTR_CalleeSavedRegisters;
struct CalleeSavedRegisters
{
    INT64 r31;  // frame pointer
    INT64 link; // link register
    INT64 r14;
    INT64 r15;
    INT64 r16;
    INT64 r17;
    INT64 r18;
    INT64 r19;
    INT64 r20;
    INT64 r21;
    INT64 r22;
    INT64 r23;
    INT64 r24;
    INT64 r25;
    INT64 r26;
    INT64 r27;
    INT64 r28;
    INT64 r29;
    INT64 r30;
};

#define NUM_ARGUMENT_REGISTERS 8
typedef DPTR(struct ArgumentRegisters) PTR_ArgumentRegisters;
struct ArgumentRegisters
{
    INT64 r[NUM_ARGUMENT_REGISTERS]; // r3-r10
};

#define ARGUMENTREGISTERS_SIZE sizeof(ArgumentRegisters)

#define NUM_FLOAT_ARGUMENT_REGISTERS 13
typedef DPTR(struct FloatArgumentRegisters) PTR_FloatArgumentRegisters;
struct FloatArgumentRegisters
{
    double f[NUM_FLOAT_ARGUMENT_REGISTERS]; // f1-f13
};

#ifdef PROFILING_SUPPORTED
struct PROFILE_PLATFORM_SPECIFIC_DATA
{
    void*                  Fp;
    void*                  Pc;
    ArgumentRegisters      argumentRegisters;
    FunctionID             functionId;
    FloatArgumentRegisters floatArgumentRegisters;
    void*                  probeSp;
    void*                  profiledSp;
    void*                  hiddenArg;
    UINT64                 flags;
    BYTE                   buffer[sizeof(ArgumentRegisters) + sizeof(FloatArgumentRegisters)];
};
#endif // PROFILING_SUPPORTED

inline PCODE GetIP(const T_CONTEXT* context)
{
    LIMITED_METHOD_DAC_CONTRACT;
    return context->Nip;
}

inline void SetIP(T_CONTEXT* context, PCODE ip)
{
    LIMITED_METHOD_DAC_CONTRACT;
    context->Nip = ip;
}

inline TADDR GetSP(const T_CONTEXT* context)
{
    LIMITED_METHOD_DAC_CONTRACT;
    return TADDR(context->R1);
}

inline void SetSP(T_CONTEXT* context, TADDR sp)
{
    LIMITED_METHOD_DAC_CONTRACT;
    context->R1 = DWORD64(sp);
}

inline TADDR GetFP(const T_CONTEXT* context)
{
    LIMITED_METHOD_DAC_CONTRACT;
    return TADDR(context->R31);
}

inline void SetFP(T_CONTEXT* context, TADDR fp)
{
    LIMITED_METHOD_DAC_CONTRACT;
    context->R31 = DWORD64(fp);
}

inline TADDR GetRA(const T_CONTEXT* context)
{
    LIMITED_METHOD_DAC_CONTRACT;
    return context->Link;
}

inline void SetRA(T_CONTEXT* context, TADDR ip)
{
    LIMITED_METHOD_DAC_CONTRACT;
    context->Link = ip;
}

inline TADDR GetReg(T_CONTEXT* context, int regNum)
{
    LIMITED_METHOD_DAC_CONTRACT;
    _ASSERTE(regNum >= 0 && regNum < 32);
    return (&context->R0)[regNum];
}

inline void SetReg(T_CONTEXT* context, int regNum, PCODE regContent)
{
    LIMITED_METHOD_DAC_CONTRACT;
    _ASSERTE(regNum >= 0 && regNum < 32);
    (&context->R0)[regNum] = regContent;
}

extern "C" void* GetCurrentSP();

inline void SetFirstArgReg(T_CONTEXT* context, TADDR value)
{
    LIMITED_METHOD_DAC_CONTRACT;
    context->R3 = DWORD64(value);
}

inline TADDR GetFirstArgReg(T_CONTEXT* context)
{
    LIMITED_METHOD_DAC_CONTRACT;
    return TADDR(context->R3);
}

inline void SetSecondArgReg(T_CONTEXT* context, TADDR value)
{
    LIMITED_METHOD_DAC_CONTRACT;
    context->R4 = DWORD64(value);
}

inline TADDR GetSecondArgReg(T_CONTEXT* context)
{
    LIMITED_METHOD_DAC_CONTRACT;
    return TADDR(context->R4);
}

inline TADDR GetMem(PCODE address, SIZE_T size, bool signExtend)
{
    TADDR mem;
    LIMITED_METHOD_DAC_CONTRACT;
    EX_TRY
    {
        switch (size)
        {
            case 4:
                mem = signExtend ? *(int32_t*)address : *(uint32_t*)address;
                break;
            case 8:
                mem = *(uint64_t*)address;
                break;
            default:
                UNREACHABLE();
        }
    }
    EX_CATCH
    {
        mem = (TADDR)NULL;
        _ASSERTE(!"Memory read within jitted code failed");
    }
    EX_END_CATCH
    return mem;
}

inline BOOL ClrFlushInstructionCache(LPCVOID pCodeAddr, size_t sizeOfCode, bool hasCodeExecutedBefore = false)
{
    return FlushInstructionCache(GetCurrentProcess(), pCodeAddr, sizeOfCode);
}

inline void emitBackToBackJump(LPBYTE pBufferRX, LPBYTE pBufferRW, LPVOID target)
{
    LIMITED_METHOD_CONTRACT;
    UINT32* pCode = (UINT32*)pBufferRW;

    // mflr  r0
    // bl    +4
    // mflr  r12
    // mtlr  r0
    // ld    r12, 24(r12)
    // mtctr r12
    // bctr
    // nop
    // [target address]
    //
    // The generated stub may be entered as part of a call sequence, so preserve
    // LR while deriving the literal address from the temporary branch-and-link.
    pCode[0] = 0x7c0802a6; // mflr  r0
    pCode[1] = 0x48000005; // bl    +4
    pCode[2] = 0x7d8802a6; // mflr  r12
    pCode[3] = 0x7c0803a6; // mtlr  r0
    pCode[4] = 0xe98c0018; // ld    r12, 24(r12)
    pCode[5] = 0x7d8903a6; // mtctr r12
    pCode[6] = 0x4e800420; // bctr
    pCode[7] = 0x60000000; // nop

    ClrFlushInstructionCache(pBufferRX, 32);

    *((LPVOID*)(pCode + 8)) = target;
}

inline PCODE decodeBackToBackJump(PCODE pCode)
{
    LIMITED_METHOD_CONTRACT;
    TADDR pInstr = PCODEToPINSTR(pCode);
    return *dac_cast<PTR_PCODE>(pInstr + 8 * sizeof(UINT32));
}

struct IntReg
{
    int reg;
    IntReg(int reg) : reg(reg)
    {
        _ASSERTE(0 <= reg && reg < 32);
    }

    operator int() { return reg; }
    operator int() const { return reg; }
    int operator==(IntReg other) { return reg == other.reg; }
    int operator!=(IntReg other) { return reg != other.reg; }
    WORD Mask() const { return 1 << reg; }
};

const IntReg RegSp = IntReg(1);
const IntReg RegFp = IntReg(31);
const IntReg RegRa = IntReg(0);

#define GetEEFuncEntryPoint(pfn) GFN_TADDR(pfn)

class StubLinkerCPU : public StubLinker
{
public:
    static void Init();
    void EmitCallManagedMethod(MethodDesc* pMD, BOOL fTailCall);
    void EmitCallLabel(CodeLabel* target, BOOL fTailCall, BOOL fIndirect);
    void EmitShuffleThunk(struct ShuffleEntry* pShuffleEntryArray);
    void EmitComputedInstantiatingMethodStub(MethodDesc* pSharedMD, struct ShuffleEntry* pShuffleEntryArray, void* extraArg);
};

#define DATA_ALIGNMENT 8

struct HijackArgs
{
    DWORD64 R31;
    union
    {
        DWORD64 Link;
        size_t  ReturnAddress;
    };
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 R16;
    DWORD64 R17;
    DWORD64 R18;
    DWORD64 R19;
    DWORD64 R20;
    DWORD64 R21;
    DWORD64 R22;
    DWORD64 R23;
    DWORD64 R24;
    DWORD64 R25;
    DWORD64 R26;
    DWORD64 R27;
    DWORD64 R28;
    DWORD64 R29;
    DWORD64 R30;
    union
    {
        struct
        {
            DWORD64 R3;
            DWORD64 R4;
        };
        size_t ReturnValue[2];
    };
    union
    {
        DWORD64 R5;
        size_t  AsyncRet;
    };
    union
    {
        struct
        {
            DWORD64 F1;
            DWORD64 F2;
        };
        size_t FPReturnValue[2];
    };
};

#endif // __cgencpu_h__
