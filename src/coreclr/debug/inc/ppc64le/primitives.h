// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef PRIMITIVES_H_
#define PRIMITIVES_H_

typedef const BYTE               CORDB_ADDRESS_TYPE;
typedef DPTR(CORDB_ADDRESS_TYPE) PTR_CORDB_ADDRESS_TYPE;

#define MAX_INSTRUCTION_LENGTH 4
#define STACKWALK_CONTROLPC_ADJUST_OFFSET 4

#define PRD_TYPE                      LONG
#define CORDbg_BREAK_INSTRUCTION_SIZE 4
#define CORDbg_BREAK_INSTRUCTION      (LONG)0x7fe00008 // trap

inline CORDB_ADDRESS GetPatchEndAddr(CORDB_ADDRESS patchAddr)
{
    LIMITED_METHOD_DAC_CONTRACT;
    return patchAddr + CORDbg_BREAK_INSTRUCTION_SIZE;
}

#define InitializePRDToBreakInst(_pPRD) *(_pPRD) = CORDbg_BREAK_INSTRUCTION
#define PRDIsBreakInst(_pPRD)           (*(_pPRD) == CORDbg_BREAK_INSTRUCTION)

#define CORDbgGetInstructionEx(_buffer, _requestedAddr, _patchAddr, _dummy1, _dummy2) \
    CORDbgGetInstructionExImpl((CORDB_ADDRESS_TYPE*)((_buffer) + (_patchAddr) - (_requestedAddr)));

#define CORDbgSetInstructionEx(_buffer, _requestedAddr, _patchAddr, _opcode, _dummy2) \
    CORDbgSetInstructionExImpl((CORDB_ADDRESS_TYPE*)((_buffer) + (_patchAddr) - (_requestedAddr)), (_opcode));

#define CORDbgInsertBreakpointEx(_buffer, _requestedAddr, _patchAddr, _dummy1, _dummy2) \
    CORDbgInsertBreakpointExImpl((CORDB_ADDRESS_TYPE*)((_buffer) + (_patchAddr) - (_requestedAddr)));

inline void CORDbgSetIP(DT_CONTEXT* context, LPVOID ip)
{
    LIMITED_METHOD_CONTRACT;
    context->Nip = (DWORD64)ip;
}

inline LPVOID CORDbgGetSP(const DT_CONTEXT* context)
{
    LIMITED_METHOD_CONTRACT;
    return (LPVOID)(size_t)(context->R1);
}

inline void CORDbgSetSP(DT_CONTEXT* context, LPVOID sp)
{
    LIMITED_METHOD_CONTRACT;
    context->R1 = (DWORD64)sp;
}

inline LPVOID CORDbgGetFP(const DT_CONTEXT* context)
{
    LIMITED_METHOD_CONTRACT;
    return (LPVOID)(size_t)(context->R31);
}

inline void CORDbgSetFP(DT_CONTEXT* context, LPVOID fp)
{
    LIMITED_METHOD_CONTRACT;
    context->R31 = (DWORD64)fp;
}

inline BOOL CompareControlRegisters(const DT_CONTEXT* pCtx1, const DT_CONTEXT* pCtx2)
{
    LIMITED_METHOD_DAC_CONTRACT;
    return ((pCtx1->Nip == pCtx2->Nip) && (pCtx1->R1 == pCtx2->R1));
}

inline void CORDbgSetInstruction(CORDB_ADDRESS_TYPE* address, PRD_TYPE instruction)
{
    LIMITED_METHOD_DAC_CONTRACT;
    TADDR ptraddr = dac_cast<TADDR>(address);
    *(PRD_TYPE*)ptraddr = instruction;
    FlushInstructionCache(GetCurrentProcess(), address, sizeof(PRD_TYPE));
}

inline PRD_TYPE CORDbgGetInstruction(UNALIGNED CORDB_ADDRESS_TYPE* address)
{
    LIMITED_METHOD_CONTRACT;
    TADDR ptraddr = dac_cast<TADDR>(address);
    return *(PRD_TYPE*)ptraddr;
}

inline CorDebugRegister ConvertRegNumToCorDebugRegister(ICorDebugInfo::RegNum reg)
{
    LIMITED_METHOD_CONTRACT;
    switch (reg)
    {
        case ICorDebugInfo::REGNUM_PC:
            return REGISTER_INSTRUCTION_POINTER;
        case ICorDebugInfo::REGNUM_R1:
            return REGISTER_STACK_POINTER;
        case ICorDebugInfo::REGNUM_R31:
            return REGISTER_FRAME_POINTER;
        default:
            return (CorDebugRegister)(REGISTER_FRAME_POINTER + 1 + reg);
    }
}

inline LPVOID CORDbgGetIP(DT_CONTEXT* context)
{
    LIMITED_METHOD_CONTRACT;
    return (LPVOID)(size_t)(context->Nip);
}

inline void CORDbgSetInstructionExImpl(CORDB_ADDRESS_TYPE* address, PRD_TYPE instruction)
{
    LIMITED_METHOD_DAC_CONTRACT;
    *(PRD_TYPE*)address = instruction;
    FlushInstructionCache(GetCurrentProcess(), address, sizeof(PRD_TYPE));
}

inline PRD_TYPE CORDbgGetInstructionExImpl(UNALIGNED CORDB_ADDRESS_TYPE* address)
{
    LIMITED_METHOD_CONTRACT;
    return *(PRD_TYPE*)address;
}

inline void CORDbgInsertBreakpoint(UNALIGNED CORDB_ADDRESS_TYPE* address)
{
    LIMITED_METHOD_CONTRACT;
    CORDbgSetInstruction(address, CORDbg_BREAK_INSTRUCTION);
}

inline void CORDbgInsertBreakpointExImpl(UNALIGNED CORDB_ADDRESS_TYPE* address)
{
    LIMITED_METHOD_CONTRACT;
    CORDbgSetInstruction(address, CORDbg_BREAK_INSTRUCTION);
}

inline void CORDbgAdjustPCForBreakInstruction(DT_CONTEXT* pContext)
{
    LIMITED_METHOD_CONTRACT;
}

inline bool AddressIsBreakpoint(CORDB_ADDRESS_TYPE* address)
{
    LIMITED_METHOD_CONTRACT;
    return CORDbgGetInstruction(address) == CORDbg_BREAK_INSTRUCTION;
}

class Thread;
void SetSSFlag(DT_CONTEXT* pCtx, Thread* pThread = nullptr);
void UnsetSSFlag(DT_CONTEXT* pCtx, Thread* pThread = nullptr);
bool IsSSFlagEnabled(DT_CONTEXT* pCtx, Thread* pThread = nullptr);

inline bool PRDIsEqual(PRD_TYPE p1, PRD_TYPE p2)
{
    return p1 == p2;
}

inline void InitializePRD(PRD_TYPE* p1)
{
    *p1 = 0;
}

inline bool PRDIsEmpty(PRD_TYPE p1)
{
    LIMITED_METHOD_CONTRACT;
    return p1 == 0;
}

#endif // PRIMITIVES_H_
