// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "common.h"
#include "dllimportcallback.h"
#include "comdelegate.h"
#include "asmconstants.h"
#include "virtualcallstub.h"
#include "jitinterface.h"
#include "codeman.h"

#ifdef PROFILING_SUPPORTED
#include "proftoeeinterfaceimpl.h"
#endif

void ClearRegDisplayArgumentAndScratchRegisters(REGDISPLAY* pRD)
{
    pRD->volatileCurrContextPointers.R0  = NULL;
    pRD->volatileCurrContextPointers.R3  = NULL;
    pRD->volatileCurrContextPointers.R4  = NULL;
    pRD->volatileCurrContextPointers.R5  = NULL;
    pRD->volatileCurrContextPointers.R6  = NULL;
    pRD->volatileCurrContextPointers.R7  = NULL;
    pRD->volatileCurrContextPointers.R8  = NULL;
    pRD->volatileCurrContextPointers.R9  = NULL;
    pRD->volatileCurrContextPointers.R10 = NULL;
    pRD->volatileCurrContextPointers.R11 = NULL;
    pRD->volatileCurrContextPointers.R12 = NULL;
}

void UpdateRegDisplayFromCalleeSavedRegisters(REGDISPLAY* pRD, CalleeSavedRegisters* pCalleeSaved)
{
    LIMITED_METHOD_CONTRACT;

    pRD->pCurrentContext->R31  = pCalleeSaved->r31;
    pRD->pCurrentContext->Link = pCalleeSaved->link;
    pRD->pCurrentContext->R14  = pCalleeSaved->r14;
    pRD->pCurrentContext->R15  = pCalleeSaved->r15;
    pRD->pCurrentContext->R16  = pCalleeSaved->r16;
    pRD->pCurrentContext->R17  = pCalleeSaved->r17;
    pRD->pCurrentContext->R18  = pCalleeSaved->r18;
    pRD->pCurrentContext->R19  = pCalleeSaved->r19;
    pRD->pCurrentContext->R20  = pCalleeSaved->r20;
    pRD->pCurrentContext->R21  = pCalleeSaved->r21;
    pRD->pCurrentContext->R22  = pCalleeSaved->r22;
    pRD->pCurrentContext->R23  = pCalleeSaved->r23;
    pRD->pCurrentContext->R24  = pCalleeSaved->r24;
    pRD->pCurrentContext->R25  = pCalleeSaved->r25;
    pRD->pCurrentContext->R26  = pCalleeSaved->r26;
    pRD->pCurrentContext->R27  = pCalleeSaved->r27;
    pRD->pCurrentContext->R28  = pCalleeSaved->r28;
    pRD->pCurrentContext->R29  = pCalleeSaved->r29;
    pRD->pCurrentContext->R30  = pCalleeSaved->r30;

    pRD->pCurrentContextPointers->R31 = (PDWORD64)&pCalleeSaved->r31;
    pRD->pCurrentContextPointers->R14 = (PDWORD64)&pCalleeSaved->r14;
    pRD->pCurrentContextPointers->R15 = (PDWORD64)&pCalleeSaved->r15;
    pRD->pCurrentContextPointers->R16 = (PDWORD64)&pCalleeSaved->r16;
    pRD->pCurrentContextPointers->R17 = (PDWORD64)&pCalleeSaved->r17;
    pRD->pCurrentContextPointers->R18 = (PDWORD64)&pCalleeSaved->r18;
    pRD->pCurrentContextPointers->R19 = (PDWORD64)&pCalleeSaved->r19;
    pRD->pCurrentContextPointers->R20 = (PDWORD64)&pCalleeSaved->r20;
    pRD->pCurrentContextPointers->R21 = (PDWORD64)&pCalleeSaved->r21;
    pRD->pCurrentContextPointers->R22 = (PDWORD64)&pCalleeSaved->r22;
    pRD->pCurrentContextPointers->R23 = (PDWORD64)&pCalleeSaved->r23;
    pRD->pCurrentContextPointers->R24 = (PDWORD64)&pCalleeSaved->r24;
    pRD->pCurrentContextPointers->R25 = (PDWORD64)&pCalleeSaved->r25;
    pRD->pCurrentContextPointers->R26 = (PDWORD64)&pCalleeSaved->r26;
    pRD->pCurrentContextPointers->R27 = (PDWORD64)&pCalleeSaved->r27;
    pRD->pCurrentContextPointers->R28 = (PDWORD64)&pCalleeSaved->r28;
    pRD->pCurrentContextPointers->R29 = (PDWORD64)&pCalleeSaved->r29;
    pRD->pCurrentContextPointers->R30 = (PDWORD64)&pCalleeSaved->r30;
}

void TransitionFrame::UpdateRegDisplay_Impl(const PREGDISPLAY pRD, bool updateFloats)
{
    pRD->IsCallerContextValid = FALSE;
    pRD->IsCallerSPValid      = FALSE;

    CalleeSavedRegisters* pCalleeSaved = GetCalleeSavedRegisters();
    UpdateRegDisplayFromCalleeSavedRegisters(pRD, pCalleeSaved);
    ClearRegDisplayArgumentAndScratchRegisters(pRD);

    pRD->pCurrentContext->Nip = GetReturnAddress();
    pRD->pCurrentContext->R1  = this->GetSP();

    SyncRegDisplayToCurrentContext(pRD);

    LOG((LF_GCROOTS, LL_INFO100000, "STACKWALK    TransitionFrame::UpdateRegDisplay_Impl(pc:%p, sp:%p)\n",
         pRD->ControlPC, pRD->SP));
}

void FaultingExceptionFrame::UpdateRegDisplay_Impl(const PREGDISPLAY pRD, bool updateFloats)
{
    LIMITED_METHOD_DAC_CONTRACT;

    memcpy(pRD->pCurrentContext, &m_ctx, sizeof(T_CONTEXT));

    pRD->ControlPC = ::GetIP(&m_ctx);
    pRD->SP        = ::GetSP(&m_ctx);

#ifdef DACCESS_COMPILE
    T_CONTEXT* pContext = pRD->pCurrentContext;
#else
    T_CONTEXT* pContext = &m_ctx;
#endif

    pRD->pCurrentContextPointers->R14 = &pContext->R14;
    pRD->pCurrentContextPointers->R15 = &pContext->R15;
    pRD->pCurrentContextPointers->R16 = &pContext->R16;
    pRD->pCurrentContextPointers->R17 = &pContext->R17;
    pRD->pCurrentContextPointers->R18 = &pContext->R18;
    pRD->pCurrentContextPointers->R19 = &pContext->R19;
    pRD->pCurrentContextPointers->R20 = &pContext->R20;
    pRD->pCurrentContextPointers->R21 = &pContext->R21;
    pRD->pCurrentContextPointers->R22 = &pContext->R22;
    pRD->pCurrentContextPointers->R23 = &pContext->R23;
    pRD->pCurrentContextPointers->R24 = &pContext->R24;
    pRD->pCurrentContextPointers->R25 = &pContext->R25;
    pRD->pCurrentContextPointers->R26 = &pContext->R26;
    pRD->pCurrentContextPointers->R27 = &pContext->R27;
    pRD->pCurrentContextPointers->R28 = &pContext->R28;
    pRD->pCurrentContextPointers->R29 = &pContext->R29;
    pRD->pCurrentContextPointers->R30 = &pContext->R30;
    pRD->pCurrentContextPointers->R31 = &pContext->R31;

    ClearRegDisplayArgumentAndScratchRegisters(pRD);

    pRD->IsCallerContextValid = FALSE;
    pRD->IsCallerSPValid      = FALSE;
}

void InlinedCallFrame::UpdateRegDisplay_Impl(const PREGDISPLAY pRD, bool updateFloats)
{
    CONTRACT_VOID
    {
        NOTHROW;
        GC_NOTRIGGER;
#ifdef PROFILING_SUPPORTED
        PRECONDITION(CORProfilerStackSnapshotEnabled() || InlinedCallFrame::FrameHasActiveCall(this));
#endif
        MODE_ANY;
        SUPPORTS_DAC;
    }
    CONTRACT_END;

    if (!InlinedCallFrame::FrameHasActiveCall(this))
    {
        LOG((LF_CORDB, LL_ERROR, "WARNING: InlinedCallFrame::UpdateRegDisplay called on inactive frame %p\n", this));
        RETURN;
    }

    pRD->IsCallerContextValid = FALSE;
    pRD->IsCallerSPValid      = FALSE;

    pRD->pCurrentContext->Nip = *(DWORD64*)&m_pCallerReturnAddress;
    pRD->pCurrentContext->R1  = *(DWORD64*)&m_pCallSiteSP;
    pRD->pCurrentContext->R31 = *(DWORD64*)&m_pCalleeSavedFP;

    memset(pRD->pCurrentContextPointers, 0, sizeof(*pRD->pCurrentContextPointers));
    pRD->pCurrentContextPointers->R31 = &m_pCalleeSavedFP;

    pRD->ControlPC = m_pCallerReturnAddress;
    pRD->SP        = (DWORD64)dac_cast<TADDR>(m_pCallSiteSP);
    pRD->pContext  = NULL;

    ClearRegDisplayArgumentAndScratchRegisters(pRD);

    RETURN;
}

#ifdef FEATURE_HIJACK
TADDR ResumableFrame::GetReturnAddressPtr_Impl(void)
{
    LIMITED_METHOD_DAC_CONTRACT;
    return dac_cast<TADDR>(m_Regs) + offsetof(T_CONTEXT, Nip);
}

void ResumableFrame::UpdateRegDisplay_Impl(const PREGDISPLAY pRD, bool updateFloats)
{
    CONTRACT_VOID
    {
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
        SUPPORTS_DAC;
    }
    CONTRACT_END;

    CopyMemory(pRD->pCurrentContext, m_Regs, sizeof(T_CONTEXT));

    pRD->ControlPC = m_Regs->Nip;
    pRD->SP        = m_Regs->R1;

    pRD->pCurrentContextPointers->R14 = &m_Regs->R14;
    pRD->pCurrentContextPointers->R15 = &m_Regs->R15;
    pRD->pCurrentContextPointers->R16 = &m_Regs->R16;
    pRD->pCurrentContextPointers->R17 = &m_Regs->R17;
    pRD->pCurrentContextPointers->R18 = &m_Regs->R18;
    pRD->pCurrentContextPointers->R19 = &m_Regs->R19;
    pRD->pCurrentContextPointers->R20 = &m_Regs->R20;
    pRD->pCurrentContextPointers->R21 = &m_Regs->R21;
    pRD->pCurrentContextPointers->R22 = &m_Regs->R22;
    pRD->pCurrentContextPointers->R23 = &m_Regs->R23;
    pRD->pCurrentContextPointers->R24 = &m_Regs->R24;
    pRD->pCurrentContextPointers->R25 = &m_Regs->R25;
    pRD->pCurrentContextPointers->R26 = &m_Regs->R26;
    pRD->pCurrentContextPointers->R27 = &m_Regs->R27;
    pRD->pCurrentContextPointers->R28 = &m_Regs->R28;
    pRD->pCurrentContextPointers->R29 = &m_Regs->R29;
    pRD->pCurrentContextPointers->R30 = &m_Regs->R30;
    pRD->pCurrentContextPointers->R31 = &m_Regs->R31;

    pRD->volatileCurrContextPointers.R0  = &m_Regs->R0;
    pRD->volatileCurrContextPointers.R3  = &m_Regs->R3;
    pRD->volatileCurrContextPointers.R4  = &m_Regs->R4;
    pRD->volatileCurrContextPointers.R5  = &m_Regs->R5;
    pRD->volatileCurrContextPointers.R6  = &m_Regs->R6;
    pRD->volatileCurrContextPointers.R7  = &m_Regs->R7;
    pRD->volatileCurrContextPointers.R8  = &m_Regs->R8;
    pRD->volatileCurrContextPointers.R9  = &m_Regs->R9;
    pRD->volatileCurrContextPointers.R10 = &m_Regs->R10;
    pRD->volatileCurrContextPointers.R11 = &m_Regs->R11;
    pRD->volatileCurrContextPointers.R12 = &m_Regs->R12;

    pRD->IsCallerContextValid = FALSE;
    pRD->IsCallerSPValid      = FALSE;

    RETURN;
}

void HijackFrame::UpdateRegDisplay_Impl(const PREGDISPLAY pRD, bool updateFloats)
{
    LIMITED_METHOD_CONTRACT;

    pRD->IsCallerContextValid = FALSE;
    pRD->IsCallerSPValid      = FALSE;

    pRD->pCurrentContext->Nip = m_ReturnAddress;
    size_t s = sizeof(struct HijackArgs);
    _ASSERTE((s % 8) == 0);
    s = s + s % 16;
    pRD->pCurrentContext->R1 = PTR_TO_TADDR(m_Args) + s;

    pRD->pCurrentContext->R3 = m_Args->R3;
    pRD->pCurrentContext->R4 = m_Args->R4;
    pRD->pCurrentContext->R5 = m_Args->R5;

    pRD->volatileCurrContextPointers.R3 = &m_Args->R3;
    pRD->volatileCurrContextPointers.R4 = &m_Args->R4;
    pRD->volatileCurrContextPointers.R5 = &m_Args->R5;

    pRD->pCurrentContext->R31  = m_Args->R31;
    pRD->pCurrentContext->Link = m_Args->Link;
    pRD->pCurrentContext->R14  = m_Args->R14;
    pRD->pCurrentContext->R15  = m_Args->R15;
    pRD->pCurrentContext->R16  = m_Args->R16;
    pRD->pCurrentContext->R17  = m_Args->R17;
    pRD->pCurrentContext->R18  = m_Args->R18;
    pRD->pCurrentContext->R19  = m_Args->R19;
    pRD->pCurrentContext->R20  = m_Args->R20;
    pRD->pCurrentContext->R21  = m_Args->R21;
    pRD->pCurrentContext->R22  = m_Args->R22;
    pRD->pCurrentContext->R23  = m_Args->R23;
    pRD->pCurrentContext->R24  = m_Args->R24;
    pRD->pCurrentContext->R25  = m_Args->R25;
    pRD->pCurrentContext->R26  = m_Args->R26;
    pRD->pCurrentContext->R27  = m_Args->R27;
    pRD->pCurrentContext->R28  = m_Args->R28;
    pRD->pCurrentContext->R29  = m_Args->R29;
    pRD->pCurrentContext->R30  = m_Args->R30;

    pRD->pCurrentContextPointers->R31 = &m_Args->R31;
    pRD->pCurrentContextPointers->R14 = &m_Args->R14;
    pRD->pCurrentContextPointers->R15 = &m_Args->R15;
    pRD->pCurrentContextPointers->R16 = &m_Args->R16;
    pRD->pCurrentContextPointers->R17 = &m_Args->R17;
    pRD->pCurrentContextPointers->R18 = &m_Args->R18;
    pRD->pCurrentContextPointers->R19 = &m_Args->R19;
    pRD->pCurrentContextPointers->R20 = &m_Args->R20;
    pRD->pCurrentContextPointers->R21 = &m_Args->R21;
    pRD->pCurrentContextPointers->R22 = &m_Args->R22;
    pRD->pCurrentContextPointers->R23 = &m_Args->R23;
    pRD->pCurrentContextPointers->R24 = &m_Args->R24;
    pRD->pCurrentContextPointers->R25 = &m_Args->R25;
    pRD->pCurrentContextPointers->R26 = &m_Args->R26;
    pRD->pCurrentContextPointers->R27 = &m_Args->R27;
    pRD->pCurrentContextPointers->R28 = &m_Args->R28;
    pRD->pCurrentContextPointers->R29 = &m_Args->R29;
    pRD->pCurrentContextPointers->R30 = &m_Args->R30;

    SyncRegDisplayToCurrentContext(pRD);
}
#endif // FEATURE_HIJACK

PTR_CONTEXT GetCONTEXTFromRedirectedStubStackFrame(T_CONTEXT* pContext)
{
    LIMITED_METHOD_DAC_CONTRACT;
    return NULL;
}

#if !defined(DACCESS_COMPILE)
BOOL AdjustContextForVirtualStub(EXCEPTION_RECORD* pExceptionRecord, CONTEXT* pContext)
{
    LIMITED_METHOD_CONTRACT;
    return FALSE;
}

VOID ResetCurrentContext()
{
    LIMITED_METHOD_CONTRACT;
}
#endif // !DACCESS_COMPILE

#ifdef FEATURE_READYTORUN
#ifndef FEATURE_STUBPRECODE_DYNAMIC_HELPERS
PCODE DynamicHelpers::CreateHelper(LoaderAllocator* pAllocator, TADDR arg, PCODE target)
{
    PORTABILITY_ASSERT("DynamicHelpers::CreateHelper is not implemented on PPC64LE");
    return NULL;
}

PCODE DynamicHelpers::CreateHelperWithArg(LoaderAllocator* pAllocator, TADDR arg, PCODE target)
{
    PORTABILITY_ASSERT("DynamicHelpers::CreateHelperWithArg is not implemented on PPC64LE");
    return NULL;
}

PCODE DynamicHelpers::CreateHelper(LoaderAllocator* pAllocator, TADDR arg, TADDR arg2, PCODE target)
{
    PORTABILITY_ASSERT("DynamicHelpers::CreateHelper is not implemented on PPC64LE");
    return NULL;
}

PCODE DynamicHelpers::CreateHelperArgMove(LoaderAllocator* pAllocator, TADDR arg, PCODE target)
{
    PORTABILITY_ASSERT("DynamicHelpers::CreateHelperArgMove is not implemented on PPC64LE");
    return NULL;
}

PCODE DynamicHelpers::CreateReturn(LoaderAllocator* pAllocator)
{
    PORTABILITY_ASSERT("DynamicHelpers::CreateReturn is not implemented on PPC64LE");
    return NULL;
}

PCODE DynamicHelpers::CreateReturnConst(LoaderAllocator* pAllocator, TADDR arg)
{
    PORTABILITY_ASSERT("DynamicHelpers::CreateReturnConst is not implemented on PPC64LE");
    return NULL;
}

PCODE DynamicHelpers::CreateReturnIndirConst(LoaderAllocator* pAllocator, TADDR arg, INT8 offset)
{
    PORTABILITY_ASSERT("DynamicHelpers::CreateReturnIndirConst is not implemented on PPC64LE");
    return NULL;
}

PCODE DynamicHelpers::CreateHelperWithTwoArgs(LoaderAllocator* pAllocator, TADDR arg, PCODE target)
{
    PORTABILITY_ASSERT("DynamicHelpers::CreateHelperWithTwoArgs is not implemented on PPC64LE");
    return NULL;
}

PCODE DynamicHelpers::CreateHelperWithTwoArgs(LoaderAllocator* pAllocator, TADDR arg, TADDR arg2, PCODE target)
{
    PORTABILITY_ASSERT("DynamicHelpers::CreateHelperWithTwoArgs is not implemented on PPC64LE");
    return NULL;
}

PCODE DynamicHelpers::CreateDictionaryLookupHelper(
    LoaderAllocator* pAllocator, CORINFO_RUNTIME_LOOKUP* pLookup, DWORD dictionaryIndexAndSlot, Module* pModule)
{
    PORTABILITY_ASSERT("DynamicHelpers::CreateDictionaryLookupHelper is not implemented on PPC64LE");
    return NULL;
}
#endif // !FEATURE_STUBPRECODE_DYNAMIC_HELPERS
#endif // FEATURE_READYTORUN

LONG CLRNoCatchHandler(EXCEPTION_POINTERS* pExceptionInfo, PVOID pv)
{
    return EXCEPTION_CONTINUE_SEARCH;
}

#ifndef DACCESS_COMPILE
void SoftwareExceptionFrame::UpdateContextFromTransitionBlock(TransitionBlock* pTransitionBlock)
{
    LIMITED_METHOD_CONTRACT;

    memset(&m_Context, 0, sizeof(m_Context));
    memset(&m_ContextPointers, 0, sizeof(m_ContextPointers));

    if (pTransitionBlock == nullptr)
    {
        m_ReturnAddress = 0;
        return;
    }

    m_Context.R1  = (UINT_PTR)(pTransitionBlock + 1);
    m_Context.Nip = pTransitionBlock->m_ReturnAddress;
    m_Context.R31 = (UINT_PTR)pTransitionBlock->m_calleeSavedRegisters.r31;
    m_Context.Link = (UINT_PTR)pTransitionBlock->m_calleeSavedRegisters.link;
    m_ReturnAddress = pTransitionBlock->m_ReturnAddress;

    FillContextPointers(&m_ContextPointers, &m_Context);
}
#endif // DACCESS_COMPILE

void FlushWriteBarrierInstructionCache()
{
}

void InitJITWriteBarrierHelpers()
{
}

int StompWriteBarrierEphemeral(bool isRuntimeSuspended)
{
    return SWB_PASS;
}

int StompWriteBarrierResize(bool isRuntimeSuspended, bool bReqUpperBoundsCheck)
{
    return SWB_PASS;
}

#ifdef FEATURE_USE_SOFTWARE_WRITE_WATCH_FOR_GC_HEAP
int SwitchToWriteWatchBarrier(bool isRuntimeSuspended)
{
    return SWB_PASS;
}

int SwitchToNonWriteWatchBarrier(bool isRuntimeSuspended)
{
    return SWB_PASS;
}
#endif // FEATURE_USE_SOFTWARE_WRITE_WATCH_FOR_GC_HEAP

#ifdef PROFILING_SUPPORTED
UINT_PTR ProfileGetIPFromPlatformSpecificHandle(void* pPlatformSpecificHandle)
{
    return 0;
}

void ProfileSetFunctionIDInPlatformSpecificHandle(void* pPlatformSpecificHandle, FunctionID functionId)
{
}

ProfileArgIterator::ProfileArgIterator(MetaSig* pSig, void* pPlatformSpecificHandle)
    : m_handle(pPlatformSpecificHandle), m_argIterator(pSig)
{
}

ProfileArgIterator::~ProfileArgIterator()
{
    m_handle = nullptr;
}

LPVOID ProfileArgIterator::GetHiddenArgValue(void)
{
    return nullptr;
}

LPVOID ProfileArgIterator::GetThis(void)
{
    return nullptr;
}

LPVOID ProfileArgIterator::GetNextArgAddr(void)
{
    return nullptr;
}

LPVOID ProfileArgIterator::GetReturnBufferAddr(void)
{
    return nullptr;
}
#endif // PROFILING_SUPPORTED

EXTERN_C void _Uppc64_init_remote()
{
}

#ifndef DACCESS_COMPILE
void StubLinkerCPU::Init()
{
}

static void Ppc64EmitLoad(StubLinkerCPU* sl, int rt, int ra, int offset)
{
    _ASSERTE(FitsInI2(offset));
    sl->Emit32(0xe8000000u | (rt << 21) | (ra << 16) | (offset & 0xffff));
}

static void Ppc64EmitStore(StubLinkerCPU* sl, int rs, int ra, int offset)
{
    _ASSERTE(FitsInI2(offset));
    sl->Emit32(0xf8000000u | (rs << 21) | (ra << 16) | (offset & 0xffff));
}

static void Ppc64EmitAddis(StubLinkerCPU* sl, int rt, int ra, unsigned imm)
{
    _ASSERTE(imm <= 0xffff);
    sl->Emit32(0x3c000000u | (rt << 21) | (ra << 16) | imm);
}

static void Ppc64EmitOri(StubLinkerCPU* sl, int ra, int rs, unsigned imm)
{
    _ASSERTE(imm <= 0xffff);
    sl->Emit32(0x60000000u | (rs << 21) | (ra << 16) | imm);
}

static void Ppc64EmitOris(StubLinkerCPU* sl, int ra, int rs, unsigned imm)
{
    _ASSERTE(imm <= 0xffff);
    sl->Emit32(0x64000000u | (rs << 21) | (ra << 16) | imm);
}

static void Ppc64EmitAddImm(StubLinkerCPU* sl, int rt, int ra, int imm)
{
    _ASSERTE(FitsInI2(imm));
    sl->Emit32(0x38000000u | (rt << 21) | (ra << 16) | (imm & 0xffff));
}

static void Ppc64EmitMovReg(StubLinkerCPU* sl, int rd, int rs)
{
    sl->Emit32(0x7c000378u | (rs << 21) | (rd << 16) | (rs << 11));
}

static void Ppc64EmitJumpRegister(StubLinkerCPU* sl, int targetReg)
{
    sl->Emit32(0x7c0903a6u | (targetReg << 21)); // mtctr targetReg
    sl->Emit32(0x4e800420u);                     // bctr
}

static void Ppc64EmitCallRegister(StubLinkerCPU* sl, int targetReg)
{
    sl->Emit32(0x7c0903a6u | (targetReg << 21)); // mtctr targetReg
    sl->Emit32(0x4e800421u);                     // bctrl
}

static void Ppc64EmitLoadImm(StubLinkerCPU* sl, int reg, UINT64 value)
{
    Ppc64EmitAddis(sl, reg, 0, static_cast<unsigned>((value >> 48) & 0xffff));
    Ppc64EmitOri(sl, reg, reg, static_cast<unsigned>((value >> 32) & 0xffff));
    sl->Emit32(0x780007c6u | (reg << 21) | (reg << 16)); // sldi reg, reg, 32
    Ppc64EmitOris(sl, reg, reg, static_cast<unsigned>((value >> 16) & 0xffff));
    Ppc64EmitOri(sl, reg, reg, static_cast<unsigned>(value & 0xffff));
}

static bool Ppc64ShuffleInRegister(UINT16 ofs)
{
    _ASSERTE(ofs != ShuffleEntry::SENTINEL);
    return (ofs & ShuffleEntry::REGMASK);
}

static bool Ppc64ShuffleIsFloating(UINT16 ofs)
{
    _ASSERTE(Ppc64ShuffleInRegister(ofs));
    return (ofs & ShuffleEntry::FPREGMASK);
}

static int Ppc64ShuffleGetRegister(UINT16 ofs)
{
    _ASSERTE(Ppc64ShuffleInRegister(ofs));
    _ASSERTE(!Ppc64ShuffleIsFloating(ofs));
    return (ofs & ShuffleEntry::OFSREGMASK) + 3; // First GPR argument register: r3
}

static unsigned Ppc64ShuffleGetStackSlot(UINT16 ofs)
{
    _ASSERTE(!Ppc64ShuffleInRegister(ofs));
    return ofs;
}

VOID StubLinkerCPU::EmitShuffleThunk(ShuffleEntry* pShuffleEntryArray)
{
    constexpr int targetReg = 12;
    constexpr int cellReg   = 11;
    constexpr int thisReg   = 3;
    constexpr int tempReg   = 0;

    Ppc64EmitLoad(this, targetReg, thisReg, DelegateObject::GetOffsetOfMethodPtrAux());
    Ppc64EmitAddImm(this, cellReg, thisReg, DelegateObject::GetOffsetOfMethodPtrAux());

    for (ShuffleEntry* entry = pShuffleEntryArray; entry->srcofs != ShuffleEntry::SENTINEL; entry++)
    {
        if (Ppc64ShuffleInRegister(entry->srcofs))
        {
            _ASSERTE(Ppc64ShuffleInRegister(entry->dstofs));
            _ASSERTE(!Ppc64ShuffleIsFloating(entry->dstofs));
            _ASSERTE(!Ppc64ShuffleIsFloating(entry->srcofs));

            Ppc64EmitMovReg(this, Ppc64ShuffleGetRegister(entry->dstofs), Ppc64ShuffleGetRegister(entry->srcofs));
        }
        else if (Ppc64ShuffleInRegister(entry->dstofs))
        {
            _ASSERTE(!Ppc64ShuffleInRegister(entry->srcofs));
            _ASSERTE(!Ppc64ShuffleIsFloating(entry->dstofs));

            Ppc64EmitLoad(this, Ppc64ShuffleGetRegister(entry->dstofs), 1,
                          Ppc64ShuffleGetStackSlot(entry->srcofs) * sizeof(void*));
        }
        else
        {
            _ASSERTE(!Ppc64ShuffleInRegister(entry->srcofs));
            _ASSERTE(!Ppc64ShuffleInRegister(entry->dstofs));

            Ppc64EmitLoad(this, tempReg, 1, Ppc64ShuffleGetStackSlot(entry->srcofs) * sizeof(void*));
            Ppc64EmitStore(this, tempReg, 1, Ppc64ShuffleGetStackSlot(entry->dstofs) * sizeof(void*));
        }
    }

    Ppc64EmitJumpRegister(this, targetReg);
}

void StubLinkerCPU::EmitCallManagedMethod(MethodDesc* pMD, BOOL fTailCall)
{
    STANDARD_VM_CONTRACT;

    PCODE target = pMD->TryGetMultiCallableAddrOfCode(CORINFO_ACCESS_PREFER_SLOT_OVER_TEMPORARY_ENTRYPOINT);
    bool  indirect = false;

    if (target == (PCODE)NULL)
    {
        target = (PCODE)pMD->GetAddrOfSlot();
        indirect = true;
    }

    Ppc64EmitLoadImm(this, 12, target);
    if (indirect)
    {
        Ppc64EmitLoad(this, 12, 12, 0);
    }

    if (fTailCall)
    {
        Ppc64EmitJumpRegister(this, 12);
    }
    else
    {
        Ppc64EmitCallRegister(this, 12);
    }
}

void StubLinkerCPU::EmitCallLabel(CodeLabel* target, BOOL fTailCall, BOOL fIndirect)
{
    PORTABILITY_ASSERT("StubLinkerCPU::EmitCallLabel is not implemented on PPC64LE");
}

VOID StubLinkerCPU::EmitComputedInstantiatingMethodStub(
    MethodDesc* pSharedMD, ShuffleEntry* pShuffleEntryArray, void* extraArg)
{
    STANDARD_VM_CONTRACT;

    for (ShuffleEntry* entry = pShuffleEntryArray; entry->srcofs != ShuffleEntry::SENTINEL; entry++)
    {
        _ASSERTE(Ppc64ShuffleInRegister(entry->dstofs));
        _ASSERTE(Ppc64ShuffleInRegister(entry->srcofs));
        _ASSERTE(!Ppc64ShuffleIsFloating(entry->dstofs));
        _ASSERTE(!Ppc64ShuffleIsFloating(entry->srcofs));
        _ASSERTE(entry->dstofs != ShuffleEntry::HELPERREG);
        _ASSERTE(entry->srcofs != ShuffleEntry::HELPERREG);

        Ppc64EmitMovReg(this, Ppc64ShuffleGetRegister(entry->dstofs), Ppc64ShuffleGetRegister(entry->srcofs));
    }

    MetaSig msig(pSharedMD);
    ArgIterator argit(&msig);

    if (argit.HasParamType())
    {
        ArgLocDesc instArgLoc;
        argit.GetParamTypeLoc(&instArgLoc);
        int hiddenReg = instArgLoc.m_idxGenReg;
        _ASSERTE(hiddenReg != -1);
        hiddenReg += 3; // First GPR argument register: r3

        if (extraArg == NULL)
        {
            if (pSharedMD->RequiresInstMethodTableArg())
            {
                Ppc64EmitLoad(this, hiddenReg, 3, 0);
            }
        }
        else
        {
            Ppc64EmitLoadImm(this, hiddenReg, reinterpret_cast<UINT64>(extraArg));
        }
    }

    if (extraArg == NULL)
    {
        Ppc64EmitAddImm(this, 3, 3, sizeof(MethodDesc*));
    }

    EmitCallManagedMethod(pSharedMD, TRUE /* tail call */);
    SetTargetMethod(pSharedMD);
}
#endif // !DACCESS_COMPILE
