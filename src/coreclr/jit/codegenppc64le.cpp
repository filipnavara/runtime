// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "jitpch.h"
#ifdef _MSC_VER
#pragma hdrstop
#endif

#if defined(TARGET_POWERPC64)

#include "codegen.h"
#include "lower.h"
#include "gcinfo.h"

void CodeGen::genFnEpilog(BasicBlock* block)
{
    NYI_POWERPC64("genFnEpilog");
}

void CodeGen::genCodeForTreeNode(GenTree* treeNode)
{
    NYI_POWERPC64("genCodeForTreeNode");
}

void CodeGen::genCodeForJumpCompare(GenTreeOpCC* tree)
{
    NYI_POWERPC64("genCodeForJumpCompare");
}

void CodeGen::genJumpToThrowHlpBlk_la(SpecialCodeKind codeKind,
                                      instruction     ins,
                                      regNumber       reg1,
                                      BasicBlock*     failBlk,
                                      regNumber       reg2)
{
    NYI_POWERPC64("genJumpToThrowHlpBlk_la");
}

bool CodeGen::genInstrWithConstant(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, ssize_t imm, regNumber tmpReg, bool inUnwindRegion)
{
    NYI_POWERPC64("genInstrWithConstant");
    return false;
}

void CodeGen::genStackPointerAdjustment(ssize_t spAdjustment, regNumber tmpReg, bool* pTmpRegIsZero, bool reportUnwindData)
{
    NYI_POWERPC64("genStackPointerAdjustment");
}

void CodeGen::genSaveCalleeSavedRegistersHelp(regMaskTP regsToSaveMask, int lowestCalleeSavedOffset)
{
    NYI_POWERPC64("genSaveCalleeSavedRegistersHelp");
}

void CodeGen::genRestoreCalleeSavedRegistersHelp(regMaskTP regsToRestoreMask,
                                                 regNumber baseReg,
                                                 int       lowestCalleeSavedOffset,
                                                 bool      reportUnwindData)
{
    NYI_POWERPC64("genRestoreCalleeSavedRegistersHelp");
}

instruction CodeGen::genGetInsForOper(GenTree* treeNode)
{
    NYI_POWERPC64("genGetInsForOper");
    return INS_invalid;
}

instruction CodeGen::genGetVolatileLdStIns(instruction currentIns, regNumber targetReg, GenTreeIndir* indir, bool* needsBarrier)
{
    assert(indir->IsVolatile());
    *needsBarrier = true;
    return currentIns;
}

bool CodeGen::genEmitOptimizedGCWriteBarrier(GCInfo::WriteBarrierForm writeBarrierForm, GenTree* addr, GenTree* data)
{
    return false;
}

int CodeGenInterface::genSPtoFPdelta() const
{
    return 0;
}

int CodeGenInterface::genTotalFrameSize() const
{
    return 0;
}

int CodeGenInterface::genCallerSPtoFPdelta() const
{
    return 0;
}

int CodeGenInterface::genCallerSPtoInitialSPdelta() const
{
    return 0;
}

void CodeGen::genCreateAndStoreGCInfo(unsigned codeSize, unsigned prologSize, unsigned epilogSize DEBUGARG(void* codePtr))
{
    NYI_POWERPC64("genCreateAndStoreGCInfo");
}

void CodeGen::genEmitHelperCall(unsigned helper, int argSize, emitAttr retSize, regNumber callTargetReg)
{
    NYI_POWERPC64("genEmitHelperCall");
}

void CodeGen::genPushCalleeSavedRegisters(regNumber initReg, bool* pInitRegZeroed)
{
    NYI_POWERPC64("genPushCalleeSavedRegisters");
}

void CodeGen::genPopCalleeSavedRegisters(bool jmpEpilog)
{
    NYI_POWERPC64("genPopCalleeSavedRegisters");
}

void CodeGen::genOSRHandleTier0CalleeSavedRegistersAndFrame()
{
    NYI_POWERPC64("genOSRHandleTier0CalleeSavedRegistersAndFrame");
}

void CodeGen::genAllocLclFrame(unsigned frameSize, regNumber initReg, bool* pInitRegZeroed, regMaskTP maskArgRegsLiveIn)
{
    NYI_POWERPC64("genAllocLclFrame");
}

void CodeGen::genZeroInitFrameUsingBlockInit(int untrLclHi, int untrLclLo, regNumber initReg, bool* pInitRegZeroed)
{
    NYI_POWERPC64("genZeroInitFrameUsingBlockInit");
}

void CodeGen::genSetGSSecurityCookie(regNumber initReg, bool* pInitRegZeroed)
{
    NYI_POWERPC64("genSetGSSecurityCookie");
}

#ifdef PROFILING_SUPPORTED
void CodeGen::genProfilingEnterCallback(regNumber initReg, bool* pInitRegZeroed)
{
    NYI_POWERPC64("genProfilingEnterCallback");
}

void CodeGen::genProfilingLeaveCallback(unsigned helper)
{
    NYI_POWERPC64("genProfilingLeaveCallback");
}
#endif // PROFILING_SUPPORTED

void CodeGen::genFuncletProlog(BasicBlock* block)
{
    NYI_POWERPC64("genFuncletProlog");
}

void CodeGen::genFuncletEpilog(BasicBlock* block)
{
    NYI_POWERPC64("genFuncletEpilog");
}

void CodeGen::genCaptureFuncletPrologEpilogInfo()
{
    NYI_POWERPC64("genCaptureFuncletPrologEpilogInfo");
}

void CodeGen::genEmitGSCookieCheck(bool tailCall)
{
    NYI_POWERPC64("genEmitGSCookieCheck");
}

void CodeGen::genJmpPlaceVarArgs()
{
    NYI_POWERPC64("genJmpPlaceVarArgs");
}

void CodeGen::genCallFinally(BasicBlock* block)
{
    NYI_POWERPC64("genCallFinally");
}

void CodeGen::genEHCatchRet(BasicBlock* block)
{
    NYI_POWERPC64("genEHCatchRet");
}

void CodeGen::genIntToIntCast(GenTreeCast* cast)
{
    NYI_POWERPC64("genIntToIntCast");
}

void CodeGen::genFloatToFloatCast(GenTree* treeNode)
{
    NYI_POWERPC64("genFloatToFloatCast");
}

void CodeGen::genFloatToIntCast(GenTree* treeNode)
{
    NYI_POWERPC64("genFloatToIntCast");
}

void CodeGen::genIntToFloatCast(GenTree* treeNode)
{
    NYI_POWERPC64("genIntToFloatCast");
}

void CodeGen::genSimpleReturn(GenTree* treeNode)
{
    NYI_POWERPC64("genSimpleReturn");
}

void CodeGen::inst_JMP(emitJumpKind jmp, BasicBlock* tgtBlock)
{
    GetEmitter()->emitIns_J(emitter::emitJumpKindToIns(jmp), tgtBlock);
}

void CodeGen::instGen_Set_Reg_To_Imm(emitAttr  size,
                                     regNumber reg,
                                     ssize_t   imm,
                                     insFlags flags DEBUGARG(size_t targetHandle) DEBUGARG(GenTreeFlags gtFlags))
{
    GetEmitter()->emitIns_R_I(INS_addi, size, reg, imm);
}

// clang-format off
const GenConditionDesc GenConditionDesc::map[32] = {};
// clang-format on

#endif // TARGET_POWERPC64
