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
#include "patchpointinfo.h"

static constexpr int PPC_LINK_REGISTER_SAVE_SIZE = REGSIZE_BYTES;
static constexpr int PPC_FRAME_POINTER_SAVE_SIZE = REGSIZE_BYTES;
static constexpr int PPC_MAX_UNWIND_SAVE_OFFSET  = 2047;
static constexpr int PPC_TOC_SAVE_OFFSET         = 24;

static instruction ppcCompareInsForCondition(GenCondition cond, emitAttr cmpSize)
{
    assert((cmpSize == EA_4BYTE) || (cmpSize == EA_8BYTE));
    return cond.IsUnsigned() ? ((cmpSize == EA_4BYTE) ? INS_cmplw : INS_cmpld)
                             : ((cmpSize == EA_4BYTE) ? INS_cmpw : INS_cmpd);
}

static emitAttr ppcNormalizeCompareSize(emitAttr cmpSize)
{
    cmpSize = EA_SIZE(cmpSize);
    assert((cmpSize == EA_1BYTE) || (cmpSize == EA_2BYTE) || (cmpSize == EA_4BYTE) || (cmpSize == EA_8BYTE));
    return (cmpSize == EA_8BYTE) ? EA_8BYTE : EA_4BYTE;
}

static instruction ppcLoadReserveIns(emitAttr attr)
{
    return (EA_SIZE(attr) == EA_4BYTE) ? INS_lwarx : INS_ldarx;
}

static instruction ppcStoreConditionalIns(emitAttr attr)
{
    return (EA_SIZE(attr) == EA_4BYTE) ? INS_stwcx : INS_stdcx;
}

static instruction ppcBranchInsForCondition(GenCondition cond)
{
    switch (cond.GetCode())
    {
        case GenCondition::EQ:
            return INS_beq;
        case GenCondition::NE:
            return INS_bne;
        case GenCondition::SLT:
        case GenCondition::ULT:
            return INS_blt;
        case GenCondition::SLE:
        case GenCondition::ULE:
            return INS_ble;
        case GenCondition::SGE:
        case GenCondition::UGE:
            return INS_bge;
        case GenCondition::SGT:
        case GenCondition::UGT:
            return INS_bgt;
        default:
            NO_WAY("unexpected PPC64LE branch condition");
            return INS_invalid;
    }
}

static void ppcEmitCompareAndBranch(emitter* emit, instruction cmpIns, regNumber reg1, regNumber reg2, instruction brIns, BasicBlock* target)
{
    emit->emitIns_R_R(cmpIns, EA_PTRSIZE, reg1, reg2);
    emit->emitIns_J(brIns, target);
}

static instruction ppcReverseBranchIns(instruction ins)
{
    switch (ins)
    {
        case INS_beq:
            return INS_bne;
        case INS_bne:
            return INS_beq;
        case INS_blt:
            return INS_bge;
        case INS_bge:
            return INS_blt;
        case INS_bgt:
            return INS_ble;
        case INS_ble:
            return INS_bgt;
        default:
            NO_WAY("unexpected PPC64LE branch instruction");
            return INS_invalid;
    }
}

static void ppcEmitBranchOnFloatRelop(emitter* emit, genTreeOps oper, BasicBlock* target)
{
    switch (oper)
    {
        case GT_EQ:
            emit->emitIns_J(INS_beq, target);
            break;
        case GT_NE:
            emit->emitIns_J(INS_blt, target);
            emit->emitIns_J(INS_bgt, target);
            break;
        case GT_LT:
            emit->emitIns_J(INS_blt, target);
            break;
        case GT_LE:
            emit->emitIns_J(INS_blt, target);
            emit->emitIns_J(INS_beq, target);
            break;
        case GT_GE:
            emit->emitIns_J(INS_bgt, target);
            emit->emitIns_J(INS_beq, target);
            break;
        case GT_GT:
            emit->emitIns_J(INS_bgt, target);
            break;
        default:
            unreached();
    }
}

static int ppcGetLclFrameOffset(Compiler* compiler, unsigned lclNum, unsigned lclOffs, regNumber* baseReg)
{
    bool fpBased = false;
    int  offset  = compiler->lvaFrameAddress(lclNum, &fpBased) + lclOffs;
    if (lclNum == compiler->lvaOutgoingArgSpaceVar)
    {
        offset += FIRST_ARG_STACK_OFFS;
    }
    *baseReg     = fpBased ? REG_FPBASE : REG_SPBASE;
    return offset;
}

static int ppcGetLclFrameOffset(Compiler* compiler, GenTreeLclVarCommon* lclNode, regNumber* baseReg)
{
    return ppcGetLclFrameOffset(compiler, lclNode->GetLclNum(), lclNode->GetLclOffs(), baseReg);
}

static bool ppcOffsetRangeFitsSimm16(int offset, unsigned size)
{
    assert(size > 0);
    ssize_t lastOffset = static_cast<ssize_t>(offset) + static_cast<ssize_t>(size) - 1;
    return emitter::isValidSimm16(offset) && emitter::isValidSimm16(lastOffset);
}

static bool ppcOffsetFitsInstruction(instruction ins, ssize_t offset)
{
    if (!emitter::isValidSimm16(offset))
    {
        return false;
    }

    switch (ins)
    {
        case INS_ld:
        case INS_std:
            return (offset & 0x3) == 0;

        case INS_lwa:
            // DS-form lwa requires a 4-byte-aligned displacement. For an
            // unaligned signed-16 displacement, genInstrWithConstant emits
            // lwz+extsw instead, so no address temporary is needed.
            return true;

        default:
            return true;
    }
}

static bool ppcLclOffsetFitsInstruction(Compiler* compiler, instruction ins, unsigned lclNum, unsigned lclOffs)
{
    regNumber baseReg = REG_NA;
    int       offset  = ppcGetLclFrameOffset(compiler, lclNum, lclOffs, &baseReg);
    return ppcOffsetFitsInstruction(ins, offset);
}

static void ppcEmitSignExtendSmallLoadIfNeeded(emitter* emit, var_types targetType, regNumber targetReg)
{
    if (targetType == TYP_BYTE)
    {
        emit->emitIns_R_R(INS_extsb, EA_PTRSIZE, targetReg, targetReg);
    }
    else if (targetType == TYP_SHORT)
    {
        emit->emitIns_R_R(INS_extsh, EA_PTRSIZE, targetReg, targetReg);
    }
}

static unsigned ppcGetDeferredFrameSizeForSaveArea(unsigned frameSize, unsigned saveAreaSize, unsigned maxDeferredSize)
{
    assert(saveAreaSize >= REGSIZE_BYTES);
    assert(maxDeferredSize <= frameSize);

    unsigned maxSaveOffset = frameSize + saveAreaSize - REGSIZE_BYTES;
    if (maxSaveOffset <= PPC_MAX_UNWIND_SAVE_OFFSET)
    {
        return 0;
    }

    // Keep the fixed save area encodable by applying most of a large local frame after saving the registers.
    return maxDeferredSize & ~(STACK_ALIGN - 1);
}

static unsigned ppcGetLocalFrameSize(Compiler* compiler, unsigned frameSize)
{
    // PPC64 ELFv2 reserves a caller-owned linkage and parameter-save area below
    // the first stack argument. Keep locals and compiler spill temps above this
    // area so helper calls made while preparing another call cannot overwrite
    // values that are live across the helper.
    return roundUp(frameSize + compiler->lvaOutgoingArgSpaceSize + FIRST_ARG_STACK_OFFS + REGSIZE_BYTES, STACK_ALIGN);
}

static unsigned ppcGetLocalFrameSize(Compiler* compiler)
{
    return ppcGetLocalFrameSize(compiler, compiler->compLclFrameSize);
}

void CodeGen::genFnEpilog(BasicBlock* block)
{
    ScopedSetVariable<bool> setGeneratingEpilog(&m_compiler->compGeneratingEpilog, true);

    VarSetOps::Assign(m_compiler, gcInfo.gcVarPtrSetCur, GetEmitter()->emitInitGCrefVars);
    gcInfo.gcRegGCrefSetCur = GetEmitter()->emitInitGCrefRegs;
    gcInfo.gcRegByrefSetCur = GetEmitter()->emitInitByrefRegs;

    m_compiler->unwindBegEpilog();

    genPopCalleeSavedRegisters(/* jmpEpilog */ false);
    GetEmitter()->emitIns(INS_blr);
    m_compiler->unwindReturn(REG_NA);

    m_compiler->unwindEndEpilog();
}

void CodeGen::genCodeForTreeNode(GenTree* treeNode)
{
#ifdef DEBUG
    // Validate that all operands for the current node are consumed in order.
    // LSRA relies on this order when it inserts copies for constrained uses.
    lastConsumedNode = nullptr;
    if (m_compiler->verbose)
    {
        unsigned seqNum = treeNode->gtSeqNum; // Useful for setting a conditional break in Visual Studio.
        m_compiler->gtDispLIRNode(treeNode, "Generating: ");
    }
#endif // DEBUG

    if (treeNode->IsReuseRegVal())
    {
        assert(treeNode->OperIs(GT_CNS_INT, GT_CNS_DBL));
        JITDUMP("  TreeNode is marked ReuseReg\n");
        return;
    }

    if (treeNode->isContained())
    {
        return;
    }

    switch (treeNode->OperGet())
    {
        case GT_START_NONGC:
            GetEmitter()->emitDisableGC();
            break;

        case GT_START_PREEMPTGC:
            gcInfo.gcMarkRegSetNpt(RBM_INT_CALLEE_SAVED);
            genDefineTempLabel(genCreateTempLabel());
            break;

        case GT_PROF_HOOK:
            noway_assert(m_compiler->compIsProfilerHookNeeded());

#ifdef PROFILING_SUPPORTED
            genProfilingLeaveCallback(CORINFO_HELP_PROF_FCN_TAILCALL);
#endif // PROFILING_SUPPORTED
            break;

        case GT_CNS_INT:
        {
            regNumber targetReg  = treeNode->GetRegNum();
            var_types targetType = treeNode->TypeGet();

            if ((targetType == TYP_DOUBLE) || (targetType == TYP_FLOAT))
            {
                treeNode->gtOper = GT_CNS_DBL;
                genSetRegToConst(targetReg, targetType, treeNode);
                genProduceReg(treeNode);
                break;
            }

            genSetRegToConst(targetReg, targetType, treeNode);
            genProduceReg(treeNode);
            break;
        }

        case GT_CNS_DBL:
        {
            regNumber targetReg  = treeNode->GetRegNum();
            var_types targetType = treeNode->TypeGet();
            genSetRegToConst(targetReg, targetType, treeNode);
            genProduceReg(treeNode);
            break;
        }

        case GT_FTN_ENTRY:
            genFtnEntry(treeNode);
            break;

        case GT_ADD:
        {
            if (varTypeIsFloating(treeNode))
            {
                genCodeForFloatingBinary(treeNode->AsOp());
                break;
            }

            GenTree*  op1       = treeNode->gtGetOp1();
            GenTree*  op2       = treeNode->gtGetOp2();
            regNumber targetReg = treeNode->GetRegNum();

            genConsumeRegs(op1);
            genConsumeRegs(op2);
            GetEmitter()->emitIns_R_R_R(INS_add, emitActualTypeSize(treeNode), targetReg, op1->GetRegNum(),
                                        op2->GetRegNum());

            if (treeNode->gtOverflow())
            {
                if (treeNode->IsUnsigned())
                {
                    GetEmitter()->emitIns_R_R((emitActualTypeSize(treeNode) == EA_8BYTE) ? INS_cmpld : INS_cmplw,
                                              emitActualTypeSize(treeNode), targetReg, op1->GetRegNum());
                    if (m_compiler->fgUseThrowHelperBlocks())
                    {
                        Compiler::AddCodeDsc* add = m_compiler->fgGetExcptnTarget(SCK_OVERFLOW, m_compiler->compCurBB);
                        assert((add != nullptr) && "failed to find overflow exception throw block");
                        assert(add->acdUsed);
                        GetEmitter()->emitIns_J(INS_blt, add->acdDstBlk);
                    }
                    else
                    {
                        BasicBlock* skipLabel = genCreateTempLabel();
                        GetEmitter()->emitIns_J(INS_bge, skipLabel);
                        genEmitHelperCall(m_compiler->acdHelper(SCK_OVERFLOW), 0, EA_UNKNOWN);
                        genDefineTempLabel(skipLabel);
                    }
                }
                else
                {
                    regNumber tempReg  = internalRegisters.Extract(treeNode);
                    regNumber tempReg2 = internalRegisters.Extract(treeNode);

                    GetEmitter()->emitIns_R_R_R(INS_xor, emitActualTypeSize(treeNode), tempReg, op1->GetRegNum(),
                                                targetReg);
                    GetEmitter()->emitIns_R_R_R(INS_xor, emitActualTypeSize(treeNode), tempReg2, op2->GetRegNum(),
                                                targetReg);
                    GetEmitter()->emitIns_R_R_R(INS_and, emitActualTypeSize(treeNode), tempReg, tempReg, tempReg2);
                    if (emitActualTypeSize(treeNode) == EA_4BYTE)
                    {
                        GetEmitter()->emitIns_R_R(INS_extsw, EA_PTRSIZE, tempReg, tempReg);
                    }
                    genJumpToThrowHlpBlk_la(SCK_OVERFLOW, INS_blt, tempReg);
                }
            }

            genProduceReg(treeNode);
            break;
        }

        case GT_SUB:
        {
            if (varTypeIsFloating(treeNode))
            {
                genCodeForFloatingBinary(treeNode->AsOp());
                break;
            }

            GenTree*  op1       = treeNode->gtGetOp1();
            GenTree*  op2       = treeNode->gtGetOp2();
            regNumber targetReg = treeNode->GetRegNum();

            genConsumeRegs(op1);
            genConsumeRegs(op2);

            if (treeNode->gtOverflow() && treeNode->IsUnsigned())
            {
                GetEmitter()->emitIns_R_R((emitActualTypeSize(treeNode) == EA_8BYTE) ? INS_cmpld : INS_cmplw,
                                          emitActualTypeSize(treeNode), op1->GetRegNum(), op2->GetRegNum());
                if (m_compiler->fgUseThrowHelperBlocks())
                {
                    Compiler::AddCodeDsc* add = m_compiler->fgGetExcptnTarget(SCK_OVERFLOW, m_compiler->compCurBB);
                    assert((add != nullptr) && "failed to find overflow exception throw block");
                    assert(add->acdUsed);
                    GetEmitter()->emitIns_J(INS_blt, add->acdDstBlk);
                }
                else
                {
                    BasicBlock* skipLabel = genCreateTempLabel();
                    GetEmitter()->emitIns_J(INS_bge, skipLabel);
                    genEmitHelperCall(m_compiler->acdHelper(SCK_OVERFLOW), 0, EA_UNKNOWN);
                    genDefineTempLabel(skipLabel);
                }
            }

            GetEmitter()->emitIns_R_R_R(INS_subf, emitActualTypeSize(treeNode), targetReg, op2->GetRegNum(),
                                        op1->GetRegNum());

            if (treeNode->gtOverflow() && !treeNode->IsUnsigned())
            {
                regNumber tempReg  = internalRegisters.Extract(treeNode);
                regNumber tempReg2 = internalRegisters.Extract(treeNode);

                GetEmitter()->emitIns_R_R_R(INS_xor, emitActualTypeSize(treeNode), tempReg, op1->GetRegNum(),
                                            op2->GetRegNum());
                GetEmitter()->emitIns_R_R_R(INS_xor, emitActualTypeSize(treeNode), tempReg2, op1->GetRegNum(),
                                            targetReg);
                GetEmitter()->emitIns_R_R_R(INS_and, emitActualTypeSize(treeNode), tempReg, tempReg, tempReg2);
                if (emitActualTypeSize(treeNode) == EA_4BYTE)
                {
                    GetEmitter()->emitIns_R_R(INS_extsw, EA_PTRSIZE, tempReg, tempReg);
                }
                genJumpToThrowHlpBlk_la(SCK_OVERFLOW, INS_blt, tempReg);
            }

            genProduceReg(treeNode);
            break;
        }

        case GT_MUL:
        {
            genCodeForMul(treeNode->AsOp());
            break;
        }

        case GT_MULHI:
            genCodeForMulHi(treeNode->AsOp());
            break;

        case GT_INC_SATURATE:
            genCodeForIncSaturate(treeNode);
            break;

        case GT_DIV:
            if (varTypeIsFloating(treeNode))
            {
                genCodeForFloatingBinary(treeNode->AsOp());
                break;
            }
            FALLTHROUGH;

        case GT_UDIV:
        case GT_MOD:
        case GT_UMOD:
            genCodeForDivMod(treeNode->AsOp());
            break;

        case GT_AND:
        case GT_AND_NOT:
        case GT_OR:
        case GT_OR_NOT:
        case GT_XOR:
        case GT_XOR_NOT:
        {
            GenTree*  op1       = treeNode->gtGetOp1();
            GenTree*  op2       = treeNode->gtGetOp2();
            regNumber targetReg = treeNode->GetRegNum();

            genConsumeRegs(op1);
            genConsumeRegs(op2);
            GetEmitter()->emitIns_R_R_R(genGetInsForOper(treeNode), emitActualTypeSize(treeNode), targetReg,
                                        op1->GetRegNum(), op2->GetRegNum());
            genProduceReg(treeNode);
            break;
        }

        case GT_LSH:
        case GT_RSH:
        case GT_RSZ:
            genCodeForShift(treeNode);
            break;

        case GT_ROL:
        case GT_ROR:
            genCodeForRotate(treeNode);
            break;

        case GT_NEG:
        case GT_NOT:
            genCodeForNegNot(treeNode->AsOp());
            break;

        case GT_EQ:
        case GT_NE:
        case GT_LT:
        case GT_LE:
        case GT_GE:
        case GT_GT:
            genCodeForCompare(treeNode->AsOp());
            break;

        case GT_INTRINSIC:
            genIntrinsic(treeNode->AsIntrinsic());
            break;

        case GT_CAST:
        {
            GenTreeCast* cast = treeNode->AsCast();
            if (varTypeIsIntegral(cast) && varTypeIsIntegral(cast->CastOp()))
            {
                genIntToIntCast(cast);
            }
            else if (varTypeIsFloating(cast) && varTypeIsFloating(cast->CastOp()))
            {
                genFloatToFloatCast(cast);
            }
            else if (varTypeIsIntegral(cast) && varTypeIsFloating(cast->CastOp()))
            {
                genFloatToIntCast(cast);
            }
            else
            {
                assert(varTypeIsFloating(cast) && varTypeIsIntegral(cast->CastOp()));
                genIntToFloatCast(cast);
            }
            break;
        }

        case GT_BITCAST:
        {
            GenTree* op1           = treeNode->gtGetOp1();
            bool     targetIsFloat = varTypeUsesFloatReg(treeNode);
            bool     sourceIsFloat = varTypeUsesFloatReg(op1);
            if (!op1->isContained() && (targetIsFloat != sourceIsFloat))
            {
                const unsigned targetSize = genTypeSize(treeNode);
                const unsigned sourceSize = genTypeSize(op1);
                noway_assert(targetSize == sourceSize);

                regNumber sourceReg = genConsumeReg(op1);
                regNumber targetReg = treeNode->GetRegNum();
                if (targetSize == 8)
                {
                    GetEmitter()->emitIns_R_R(targetIsFloat ? INS_mtfprd : INS_mffprd, EA_8BYTE, targetReg,
                                              sourceReg);
                }
                else if (targetIsFloat)
                {
                    // Move the raw single bits into the high half of a doubleword, then convert
                    // from single-precision VSX format to the scalar single value representation.
                    regNumber tmpReg = internalRegisters.GetSingle(treeNode);
                    GetEmitter()->emitIns_R_R_I(INS_sldi, EA_8BYTE, tmpReg, sourceReg, 32);
                    GetEmitter()->emitIns_R_R(INS_mtfprd, EA_8BYTE, targetReg, tmpReg);
                    GetEmitter()->emitIns_R_R(INS_xscvspdpn, EA_4BYTE, targetReg, targetReg);
                }
                else
                {
                    // Convert the scalar single value to single-precision VSX format before extracting its raw bits.
                    regNumber tmpReg = internalRegisters.GetSingle(treeNode);
                    GetEmitter()->emitIns_R_R(INS_xscvdpspn, EA_4BYTE, tmpReg, sourceReg);
                    GetEmitter()->emitIns_R_R(INS_mffprwz, EA_4BYTE, targetReg, tmpReg);
                }
                genProduceReg(treeNode);
                break;
            }

            genCodeForBitCast(treeNode->AsOp());
            break;
        }

        case GT_BSWAP:
        case GT_BSWAP16:
            genCodeForBswap(treeNode);
            break;

        case GT_LCL_VAR:
            genCodeForLclVar(treeNode->AsLclVar());
            break;

        case GT_LCL_FLD:
            genCodeForLclFld(treeNode->AsLclFld());
            break;

        case GT_LCL_ADDR:
            genCodeForLclAddr(treeNode->AsLclFld());
            break;

        case GT_LEA:
            genLeaInstruction(treeNode->AsAddrMode());
            break;

        case GT_INDEX_ADDR:
            genCodeForIndexAddr(treeNode->AsIndexAddr());
            break;

        case GT_STORE_LCL_VAR:
            genCodeForStoreLclVar(treeNode->AsLclVar());
            break;

        case GT_STORE_LCL_FLD:
            genCodeForStoreLclFld(treeNode->AsLclFld());
            break;

        case GT_IND:
            genCodeForIndir(treeNode->AsIndir());
            break;

        case GT_NULLCHECK:
            genCodeForNullCheck(treeNode->AsIndir());
            break;

        case GT_STOREIND:
            genCodeForStoreInd(treeNode->AsStoreInd());
            break;

        case GT_XCHG:
        case GT_XADD:
        case GT_XORR:
        case GT_XAND:
            genLockedInstructions(treeNode->AsOp());
            break;

        case GT_CMPXCHG:
            genCodeForCmpXchg(treeNode->AsCmpXchg());
            break;

        case GT_JMP:
            genJmpPlaceArgs(treeNode);
            break;

        case GT_STORE_BLK:
            genCodeForStoreBlk(treeNode->AsBlk());
            break;

        case GT_LCLHEAP:
            genLclHeap(treeNode);
            break;

        case GT_PUTARG_STK:
            genPutArgStk(treeNode->AsPutArgStk());
            break;

        case GT_PUTARG_REG:
            genPutArgReg(treeNode->AsOp());
            break;

        case GT_CALL:
            genCall(treeNode->AsCall());
            break;

        case GT_JMPTABLE:
            genJumpTable(treeNode);
            break;

        case GT_SWITCH_TABLE:
            genTableBasedSwitch(treeNode);
            break;

        case GT_PHYSREG:
            genCodeForPhysReg(treeNode->AsPhysReg());
            break;

        case GT_CATCH_ARG:
            genCodeForCatchArg(treeNode);
            break;

        case GT_LABEL:
            genPendingCallLabel = genCreateTempLabel();
            GetEmitter()->emitIns_R_L(INS_addi, EA_PTRSIZE, genPendingCallLabel, treeNode->GetRegNum());
            break;

        case GT_JCMP:
            genCodeForJumpCompare(treeNode->AsOpCC());
            break;

        case GT_BOUNDS_CHECK:
            genRangeCheck(treeNode);
            break;

        case GT_RETURNTRAP:
            genCodeForReturnTrap(treeNode->AsOp());
            break;

        case GT_PATCHPOINT:
        case GT_PATCHPOINT_FORCED:
            genPatchpoint(treeNode->AsOp());
            break;

        case GT_RETURN:
        case GT_RETFILT:
            genReturn(treeNode);
            break;

        case GT_RETURN_SUSPEND:
            genReturnSuspend(treeNode->AsUnOp());
            break;

        case GT_ASYNC_CONTINUATION:
            genCodeForAsyncContinuation(treeNode);
            break;

        case GT_ASYNC_RESUME_INFO:
            genAsyncResumeInfo(treeNode->AsVal());
            break;

        case GT_RECORD_ASYNC_RESUME:
            genRecordAsyncResume(treeNode->AsVal());
            break;

        case GT_NONLOCAL_JMP:
            genNonLocalJmp(treeNode->AsUnOp());
            break;

        case GT_MEMORYBARRIER:
        {
            BarrierKind barrierKind =
                treeNode->gtFlags & GTF_MEMORYBARRIER_LOAD
                    ? BARRIER_LOAD_ONLY
                    : (treeNode->gtFlags & GTF_MEMORYBARRIER_STORE ? BARRIER_STORE_ONLY : BARRIER_FULL);

            instGen_MemoryBarrier(barrierKind);
            break;
        }

        case GT_RELOAD:
        case GT_COPY:
        case GT_NOP:
        case GT_IL_OFFSET:
            break;

        case GT_KEEPALIVE:
            if (treeNode->AsOp()->gtOp1->isContained())
            {
                genUpdateLife(treeNode->AsOp()->gtOp1);
            }
            else
            {
                genConsumeReg(treeNode->AsOp()->gtOp1);
            }
            break;

        case GT_NO_OP:
            GetEmitter()->emitIns(INS_nop);
            break;

        default:
            NYI_POWERPC64("genCodeForTreeNode");
            break;
    }
}

void CodeGen::genCodeForNegNot(GenTreeOp* tree)
{
    assert(tree->OperIs(GT_NEG, GT_NOT));

    GenTree* operand = tree->gtGetOp1();
    regNumber operandReg = genConsumeReg(operand);
    regNumber targetReg  = tree->GetRegNum();

    assert(targetReg != REG_NA);
    assert(tree->OperIs(GT_NEG) || !varTypeIsFloating(tree));

    GetEmitter()->emitIns_R_R(genGetInsForOper(tree), emitActualTypeSize(tree), targetReg, operandReg);

    genProduceReg(tree);
}

void CodeGen::genCodeForFloatingBinary(GenTreeOp* tree)
{
    assert(tree->OperIs(GT_ADD, GT_SUB, GT_MUL, GT_DIV));
    assert(varTypeIsFloating(tree));

    GenTree* op1 = tree->gtGetOp1();
    GenTree* op2 = tree->gtGetOp2();

    genConsumeOperands(tree);

    GetEmitter()->emitIns_R_R_R(genGetInsForOper(tree), emitActualTypeSize(tree), tree->GetRegNum(),
                                op1->GetRegNum(), op2->GetRegNum());

    genProduceReg(tree);
}

void CodeGen::genIntrinsic(GenTreeIntrinsic* treeNode)
{
    GenTree* op1 = treeNode->gtGetOp1();

    assert(varTypeIsFloating(treeNode));
    assert(op1->TypeIs(treeNode->TypeGet()));

    instruction ins = INS_invalid;
    switch (treeNode->gtIntrinsicName)
    {
        case NI_System_Math_Abs:
            ins = INS_fabs;
            break;
        case NI_System_Math_Sqrt:
            ins = (treeNode->TypeGet() == TYP_FLOAT) ? INS_fsqrts : INS_fsqrt;
            break;
        default:
            NO_WAY("Unknown intrinsic");
    }

    regNumber srcReg = genConsumeReg(op1);
    GetEmitter()->emitIns_R_R(ins, emitActualTypeSize(treeNode), treeNode->GetRegNum(), srcReg);
    genProduceReg(treeNode);
}

void CodeGen::genCodeForMul(GenTreeOp* tree)
{
    assert(tree->OperIs(GT_MUL));

    if (varTypeIsFloating(tree))
    {
        genCodeForFloatingBinary(tree);
        return;
    }

    GenTree*  op1       = tree->gtGetOp1();
    GenTree*  op2       = tree->gtGetOp2();
    regNumber targetReg = tree->GetRegNum();

    genConsumeOperands(tree);

    emitAttr attr = emitActualTypeSize(tree);
    if (!tree->gtOverflow())
    {
        GetEmitter()->emitIns_R_R_R(genGetInsForOper(tree), attr, targetReg, op1->GetRegNum(), op2->GetRegNum());
        genProduceReg(tree);
        return;
    }

    regNumber highReg = internalRegisters.Extract(tree);
    instruction highIns;
    if (EA_SIZE(attr) == EA_8BYTE)
    {
        highIns = tree->IsUnsigned() ? INS_mulhdu : INS_mulhd;
    }
    else
    {
        assert(EA_SIZE(attr) == EA_4BYTE);
        highIns = tree->IsUnsigned() ? INS_mulhwu : INS_mulhw;
    }

    GetEmitter()->emitIns_R_R_R(highIns, attr, highReg, op1->GetRegNum(), op2->GetRegNum());
    GetEmitter()->emitIns_R_R_R(genGetInsForOper(tree), attr, targetReg, op1->GetRegNum(), op2->GetRegNum());

    if (EA_SIZE(attr) == EA_4BYTE)
    {
        if (tree->IsUnsigned())
        {
            GetEmitter()->emitIns_R_R_I(INS_clrldi, EA_PTRSIZE, highReg, highReg, 32);
        }
        else
        {
            GetEmitter()->emitIns_R_R(INS_extsw, EA_PTRSIZE, highReg, highReg);
        }
    }

    if (tree->IsUnsigned())
    {
        genJumpToThrowHlpBlk_la(SCK_OVERFLOW, INS_bne, highReg);
    }
    else
    {
        regNumber signReg = internalRegisters.Extract(tree);
        unsigned  shift   = (EA_SIZE(attr) == EA_8BYTE) ? 63 : 31;

        instGen_Set_Reg_To_Imm(EA_PTRSIZE, signReg, shift);
        GetEmitter()->emitIns_R_R_R((EA_SIZE(attr) == EA_8BYTE) ? INS_srad : INS_sraw, EA_PTRSIZE, signReg, targetReg,
                                    signReg);
        genJumpToThrowHlpBlk_la(SCK_OVERFLOW, INS_bne, highReg, nullptr, signReg);
    }

    genProduceReg(tree);
}

void CodeGen::genSetRegToConst(regNumber targetReg, var_types targetType, GenTree* tree)
{
    switch (tree->OperGet())
    {
        case GT_CNS_INT:
        {
            GenTreeIntCon* con    = tree->AsIntCon();
            ssize_t        cnsVal = con->IconValue();

            emitAttr attr = emitActualTypeSize(targetType);
            if (TargetOS::IsUnix && m_compiler->IsTargetAbi(CORINFO_NATIVEAOT_ABI) && con->IsTlsIconHandle())
            {
                attr = EA_SET_FLG(attr, EA_CNS_RELOC_FLG | EA_CNS_TLSGD_RELOC);
                instGen_Set_Reg_To_Imm(attr, targetReg, cnsVal,
                                       INS_FLAGS_DONT_CARE DEBUGARG(con->gtTargetHandle) DEBUGARG(con->gtFlags));
                regSet.verifyRegUsed(targetReg);
                break;
            }

            if (TargetOS::IsUnix && con->IsIconHandle(GTF_ICON_TLS_HDL))
            {
                if (cnsVal == 0)
                {
                    GetEmitter()->emitIns_R_R(INS_mov, attr, targetReg, REG_TP);
                    regSet.verifyRegUsed(targetReg);
                    break;
                }
            }

            if (con->ImmedValNeedsReloc(m_compiler))
            {
                attr = EA_SET_FLG(attr, EA_CNS_RELOC_FLG);
            }

            if (targetType == TYP_BYREF)
            {
                attr = EA_SET_FLG(attr, EA_BYREF_FLG);
            }

            instGen_Set_Reg_To_Imm(attr, targetReg, cnsVal,
                                   INS_FLAGS_DONT_CARE DEBUGARG(con->gtTargetHandle) DEBUGARG(con->gtFlags));
            regSet.verifyRegUsed(targetReg);
            break;
        }

        case GT_CNS_DBL:
        {
            assert(varTypeUsesFloatReg(targetType));
            assert(emitter::isFloatReg(targetReg));

            emitAttr size       = emitActualTypeSize(tree);
            double   constValue = tree->AsDblCon()->DconValue();

            CORINFO_FIELD_HANDLE hnd     = GetEmitter()->emitFltOrDblConst(constValue, size);
            instruction          loadIns = (size == EA_4BYTE) ? INS_lfs : INS_lfd;
            regNumber            addrReg = internalRegisters.GetSingle(tree);

            GetEmitter()->emitIns_R_C(loadIns, size, targetReg, addrReg, hnd);
            break;
        }

        default:
            unreached();
    }
}

void CodeGen::genCodeForShift(GenTree* tree)
{
    assert(tree->OperIsShift());
    assert(!varTypeIsFloating(tree));

    GenTree* operand = tree->gtGetOp1();
    GenTree* shiftBy = tree->gtGetOp2();

    genConsumeOperands(tree->AsOp());

    GetEmitter()->emitIns_R_R_R(genGetInsForOper(tree), emitActualTypeSize(tree), tree->GetRegNum(),
                                operand->GetRegNum(), shiftBy->GetRegNum());

    genProduceReg(tree);
}

void CodeGen::genCodeForRotate(GenTree* tree)
{
    assert(tree->OperIs(GT_ROL, GT_ROR));
    assert(!varTypeIsFloating(tree));

    GenTree* operand = tree->gtGetOp1();
    GenTree* shiftBy = tree->gtGetOp2();

    genConsumeOperands(tree->AsOp());

    emitAttr  attr       = emitActualTypeSize(tree);
    regNumber targetReg  = tree->GetRegNum();
    regNumber operandReg = operand->GetRegNum();
    unsigned  width      = (attr == EA_4BYTE) ? 32 : 64;
    unsigned  countMask  = width - 1;

    if (shiftBy->IsCnsIntOrI())
    {
        unsigned rotateLeft = static_cast<unsigned>(shiftBy->AsIntCon()->gtIconVal) & countMask;
        if (tree->OperIs(GT_ROR))
        {
            rotateLeft = (width - rotateLeft) & countMask;
        }

        if (attr == EA_4BYTE)
        {
            GetEmitter()->emitIns_R_R_I_I_I(INS_rlwinm, attr, targetReg, operandReg, rotateLeft, 0, 31);
        }
        else
        {
            GetEmitter()->emitIns_R_R_I_I(INS_rldicl, attr, targetReg, operandReg, rotateLeft, 0);
        }
    }
    else
    {
        regNumber shiftByReg = shiftBy->GetRegNum();
        if (tree->OperIs(GT_ROR))
        {
            regNumber tempReg = internalRegisters.GetSingle(tree);
            GetEmitter()->emitIns_R_R(INS_neg, attr, tempReg, shiftByReg);
            shiftByReg = tempReg;
        }

        if (attr == EA_4BYTE)
        {
            GetEmitter()->emitIns_R_R_R_I_I(INS_rlwnm, attr, targetReg, operandReg, shiftByReg, 0, 31);
        }
        else
        {
            GetEmitter()->emitIns_R_R_R_I(INS_rldcl, attr, targetReg, operandReg, shiftByReg, 0);
        }
    }

    genProduceReg(tree);
}

void CodeGen::genCodeForBswap(GenTree* tree)
{
    assert(tree->OperIs(GT_BSWAP, GT_BSWAP16));

    GenTree*  operand   = tree->gtGetOp1();
    regNumber sourceReg = genConsumeReg(operand);
    regNumber targetReg = tree->GetRegNum();
    regNumber tempReg   = internalRegisters.GetSingle(tree);

    unsigned byteCount = tree->OperIs(GT_BSWAP16) ? 2 : genTypeSize(genActualType(tree));
    assert((byteCount == 2) || (byteCount == 4) || (byteCount == 8));

    auto extractByte = [=](regNumber dstReg, unsigned sourceByte) {
        unsigned shift = sourceByte * BITS_PER_BYTE;
        if (shift == 0)
        {
            GetEmitter()->emitIns_Mov(EA_PTRSIZE, dstReg, sourceReg, false);
        }
        else
        {
            instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_R0, shift);
            GetEmitter()->emitIns_R_R_R(INS_srd, EA_PTRSIZE, dstReg, sourceReg, REG_R0);
        }

        instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_R0, 0xFF);
        GetEmitter()->emitIns_R_R_R(INS_and, EA_PTRSIZE, dstReg, dstReg, REG_R0);
    };

    auto shiftByteLeft = [=](regNumber reg, unsigned shift) {
        assert(shift < 64);
        if (shift != 0)
        {
            instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_R0, shift);
            GetEmitter()->emitIns_R_R_R(INS_sld, EA_PTRSIZE, reg, reg, REG_R0);
        }
    };

    extractByte(targetReg, byteCount - 1);

    for (unsigned sourceByte = 0; sourceByte < byteCount - 1; sourceByte++)
    {
        extractByte(tempReg, sourceByte);
        shiftByteLeft(tempReg, (byteCount - 1 - sourceByte) * BITS_PER_BYTE);
        GetEmitter()->emitIns_R_R_R(INS_or, EA_PTRSIZE, targetReg, targetReg, tempReg);
    }

    genProduceReg(tree);
}

void CodeGen::genCodeForDivMod(GenTreeOp* tree)
{
    assert(tree->OperIs(GT_DIV, GT_UDIV, GT_MOD, GT_UMOD));
    NYI_IF(varTypeIsFloating(tree), "floating point div/mod");

    GenTree*  op1       = tree->gtGetOp1();
    GenTree*  op2       = tree->gtGetOp2();
    emitAttr  attr      = emitActualTypeSize(tree);
    regNumber targetReg = tree->GetRegNum();

    genConsumeRegs(op1);
    genConsumeRegs(op2);

    regNumber dividendReg = op1->GetRegNum();
    regNumber divisorReg  = op2->GetRegNum();

    ExceptionSetFlags exceptions = tree->OperExceptions(m_compiler);
    if ((exceptions & ExceptionSetFlags::DivideByZeroException) != ExceptionSetFlags::None)
    {
        genJumpToThrowHlpBlk_la(SCK_DIV_BY_ZERO, INS_beq, divisorReg);
    }

    regNumber tempReg = REG_NA;

    if (tree->OperIs(GT_DIV, GT_MOD) &&
        ((exceptions & ExceptionSetFlags::ArithmeticException) != ExceptionSetFlags::None))
    {
        tempReg = internalRegisters.GetSingle(tree);

        instGen_Set_Reg_To_Imm(attr, tempReg, -1);
        GetEmitter()->emitIns_R_R((attr == EA_4BYTE) ? INS_cmpw : INS_cmpd, attr, divisorReg, tempReg);

        BasicBlock* divLabel = genCreateTempLabel();
        GetEmitter()->emitIns_J(INS_bne, divLabel);

        ssize_t minValue = (attr == EA_4BYTE) ? INT32_MIN : INT64_MIN;
        instGen_Set_Reg_To_Imm(attr, tempReg, minValue);
        GetEmitter()->emitIns_R_R((attr == EA_4BYTE) ? INS_cmpw : INS_cmpd, attr, dividendReg, tempReg);

        if (m_compiler->fgUseThrowHelperBlocks())
        {
            Compiler::AddCodeDsc* add = m_compiler->fgGetExcptnTarget(SCK_ARITH_EXCPN, m_compiler->compCurBB);
            assert((add != nullptr) && "failed to find arithmetic exception throw block");
            assert(add->acdUsed);

            GetEmitter()->emitIns_J(INS_beq, add->acdDstBlk);
        }
        else
        {
            BasicBlock* skipLabel = genCreateTempLabel();
            GetEmitter()->emitIns_J(INS_bne, skipLabel);

            genEmitHelperCall(m_compiler->acdHelper(SCK_ARITH_EXCPN), 0, EA_UNKNOWN);

            genDefineTempLabel(skipLabel);
        }

        genDefineTempLabel(divLabel);
    }

    instruction divIns = genGetInsForOper(tree);
    if (tree->OperIs(GT_DIV, GT_UDIV))
    {
        GetEmitter()->emitIns_R_R_R(divIns, attr, targetReg, dividendReg, divisorReg);
    }
    else
    {
        regNumber quotientReg = (tempReg != REG_NA) ? tempReg : internalRegisters.GetSingle(tree);
        instruction mulIns    = (attr == EA_4BYTE) ? INS_mullw : INS_mulld;

        GetEmitter()->emitIns_R_R_R(divIns, attr, quotientReg, dividendReg, divisorReg);
        GetEmitter()->emitIns_R_R_R(mulIns, attr, quotientReg, quotientReg, divisorReg);
        GetEmitter()->emitIns_R_R_R(INS_subf, attr, targetReg, quotientReg, dividendReg);
    }

    genProduceReg(tree);
}

//------------------------------------------------------------------------
// genLockedInstructions: Generate code for a GT_XADD, GT_XAND, GT_XORR, or GT_XCHG node.
//
// Arguments:
//    treeNode - the GT_XADD/XAND/XORR/XCHG node
//
void CodeGen::genLockedInstructions(GenTreeOp* treeNode)
{
    assert(treeNode->OperIs(GT_XADD, GT_XAND, GT_XORR, GT_XCHG));
    assert(!varTypeIsSmall(treeNode->TypeGet()));

    GenTree*  addr      = treeNode->gtGetOp1();
    GenTree*  data      = treeNode->gtGetOp2();
    regNumber addrReg   = addr->GetRegNum();
    regNumber dataReg   = data->GetRegNum();
    regNumber targetReg = treeNode->GetRegNum();

    regNumber loadReg = targetReg;
    if (loadReg == REG_NA)
    {
        loadReg = internalRegisters.Extract(treeNode);
    }

    regNumber storeDataReg = dataReg;
    if (!treeNode->OperIs(GT_XCHG))
    {
        storeDataReg = internalRegisters.Extract(treeNode);
    }

    noway_assert(addrReg != REG_NA);
    noway_assert(dataReg != REG_NA);
    noway_assert(loadReg != REG_NA);
    noway_assert(storeDataReg != REG_NA);
    noway_assert(loadReg != addrReg);
    noway_assert(loadReg != dataReg);
    noway_assert(treeNode->OperIs(GT_XCHG) || (storeDataReg != addrReg));
    noway_assert(treeNode->OperIs(GT_XCHG) || (storeDataReg != dataReg));
    noway_assert(treeNode->OperIs(GT_XCHG) || (storeDataReg != loadReg));

    genConsumeAddress(addr);
    genConsumeRegs(data);

    emitAttr attr = emitActualTypeSize(treeNode);
    attr          = (EA_SIZE(attr) == EA_4BYTE) ? EA_4BYTE : EA_8BYTE;

    // genConsumeAddress assumes the address dies at the first instruction. The
    // reservation loop reuses it until the conditional store succeeds.
    gcInfo.gcMarkRegPtrVal(addrReg, addr->TypeGet());

    instGen_MemoryBarrier(BARRIER_FULL);

    BasicBlock* retryLabel = genCreateTempLabel();
    genDefineTempLabel(retryLabel);

    GetEmitter()->emitIns_R_R_R(ppcLoadReserveIns(attr), attr, loadReg, REG_R0, addrReg);

    switch (treeNode->OperGet())
    {
        case GT_XADD:
            GetEmitter()->emitIns_R_R_R(INS_add, attr, storeDataReg, loadReg, dataReg);
            break;
        case GT_XAND:
            GetEmitter()->emitIns_R_R_R(INS_and, attr, storeDataReg, loadReg, dataReg);
            break;
        case GT_XORR:
            GetEmitter()->emitIns_R_R_R(INS_or, attr, storeDataReg, loadReg, dataReg);
            break;
        case GT_XCHG:
            assert(storeDataReg == dataReg);
            break;
        default:
            unreached();
    }

    GetEmitter()->emitIns_R_R_R(ppcStoreConditionalIns(attr), attr, storeDataReg, REG_R0, addrReg);
    GetEmitter()->emitIns_J(INS_bne, retryLabel);

    instGen_MemoryBarrier(BARRIER_FULL);

    gcInfo.gcMarkRegSetNpt(addr->gtGetRegMask());

    if (targetReg != REG_NA)
    {
        genProduceReg(treeNode);
    }
}

//------------------------------------------------------------------------
// genCodeForCmpXchg: Produce code for a GT_CMPXCHG node.
//
// Arguments:
//    treeNode - the GT_CMPXCHG node
//
void CodeGen::genCodeForCmpXchg(GenTreeCmpXchg* treeNode)
{
    assert(treeNode->OperIs(GT_CMPXCHG));
    assert(!varTypeIsSmall(treeNode->TypeGet()));

    GenTree* addr      = treeNode->Addr();
    GenTree* data      = treeNode->Data();
    GenTree* comparand = treeNode->Comparand();

    regNumber addrReg      = addr->GetRegNum();
    regNumber dataReg      = data->GetRegNum();
    regNumber comparandReg = comparand->GetRegNum();
    regNumber targetReg    = treeNode->GetRegNum();

    noway_assert(addrReg != REG_NA);
    noway_assert(dataReg != REG_NA);
    noway_assert(comparandReg != REG_NA);
    noway_assert(targetReg != REG_NA);
    noway_assert(targetReg != addrReg);
    noway_assert(targetReg != dataReg);
    noway_assert(targetReg != comparandReg);

    genConsumeAddress(addr);
    genConsumeRegs(data);
    genConsumeRegs(comparand);

    emitAttr attr = emitActualTypeSize(treeNode);
    attr          = (EA_SIZE(attr) == EA_4BYTE) ? EA_4BYTE : EA_8BYTE;

    gcInfo.gcMarkRegPtrVal(addrReg, addr->TypeGet());

    instGen_MemoryBarrier(BARRIER_FULL);

    BasicBlock* retryLabel = genCreateTempLabel();
    BasicBlock* doneLabel  = genCreateTempLabel();

    genDefineTempLabel(retryLabel);

    GetEmitter()->emitIns_R_R_R(ppcLoadReserveIns(attr), attr, targetReg, REG_R0, addrReg);
    GetEmitter()->emitIns_R_R((EA_SIZE(attr) == EA_4BYTE) ? INS_cmpw : INS_cmpd, attr, targetReg, comparandReg);
    GetEmitter()->emitIns_J(INS_bne, doneLabel);
    GetEmitter()->emitIns_R_R_R(ppcStoreConditionalIns(attr), attr, dataReg, REG_R0, addrReg);
    GetEmitter()->emitIns_J(INS_bne, retryLabel);

    genDefineTempLabel(doneLabel);

    instGen_MemoryBarrier(BARRIER_FULL);

    gcInfo.gcMarkRegSetNpt(addr->gtGetRegMask());
    genProduceReg(treeNode);
}

//------------------------------------------------------------------------
// genCodeForMulHi: Produce code for a GT_MULHI node.
//
// Arguments:
//    tree - the GT_MULHI node
//
void CodeGen::genCodeForMulHi(GenTreeOp* tree)
{
    assert(tree->OperIs(GT_MULHI));
    assert(!tree->gtOverflowEx());
    assert(!varTypeIsFloating(tree));

    GenTree* op1 = tree->gtGetOp1();
    GenTree* op2 = tree->gtGetOp2();

    genConsumeOperands(tree);

    emitAttr    attr = emitActualTypeSize(tree);
    instruction ins;
    if (EA_SIZE(attr) == EA_8BYTE)
    {
        ins = tree->IsUnsigned() ? INS_mulhdu : INS_mulhd;
    }
    else
    {
        assert(EA_SIZE(attr) == EA_4BYTE);
        ins = tree->IsUnsigned() ? INS_mulhwu : INS_mulhw;
    }

    GetEmitter()->emitIns_R_R_R(ins, attr, tree->GetRegNum(), op1->GetRegNum(), op2->GetRegNum());

    genProduceReg(tree);
}

//------------------------------------------------------------------------
// genCodeForIncSaturate: Produce code for a GT_INC_SATURATE node.
//
// Arguments:
//    tree - the GT_INC_SATURATE node
//
void CodeGen::genCodeForIncSaturate(GenTree* tree)
{
    assert(tree->OperIs(GT_INC_SATURATE));

    regNumber targetReg = tree->GetRegNum();
    assert(targetReg != REG_NA);

    GenTree*  operand    = tree->gtGetOp1();
    regNumber operandReg = genConsumeReg(operand);
    emitAttr  attr       = emitActualTypeSize(tree);

    assert(EA_SIZE(attr) == EA_PTRSIZE);
    noway_assert(targetReg != operandReg);

    instGen_Set_Reg_To_Imm(attr, REG_R0, -1);
    GetEmitter()->emitIns_R_R(INS_cmpld, attr, operandReg, REG_R0);

    BasicBlock* doneLabel = genCreateTempLabel();

    instGen_Set_Reg_To_Imm(attr, targetReg, 0);
    GetEmitter()->emitIns_J(INS_beq, doneLabel);
    instGen_Set_Reg_To_Imm(attr, targetReg, 1);

    genDefineTempLabel(doneLabel);
    GetEmitter()->emitIns_R_R_R(INS_add, attr, targetReg, operandReg, targetReg);

    genProduceReg(tree);
}

//------------------------------------------------------------------------
// genCodeForReturnTrap: Produce code for a GT_RETURNTRAP node.
//
// Arguments:
//    tree - the GT_RETURNTRAP node
//
void CodeGen::genCodeForReturnTrap(GenTreeOp* tree)
{
    assert(tree->OperIs(GT_RETURNTRAP));

    GenTree* data = tree->gtOp1;
    genConsumeRegs(data);

    instGen_Set_Reg_To_Imm(EA_4BYTE, REG_R0, 0);
    GetEmitter()->emitIns_R_R(INS_cmpw, EA_4BYTE, data->GetRegNum(), REG_R0);

    BasicBlock* skipLabel = genCreateTempLabel();
    GetEmitter()->emitIns_J(INS_beq, skipLabel);

    genEmitHelperCall(CORINFO_HELP_STOP_FOR_GC, 0, EA_UNKNOWN);

    genDefineTempLabel(skipLabel);
}

void CodeGen::genCodeForCompare(GenTreeOp* tree)
{
    assert(tree->OperIsCmpCompare());
    assert(!tree->TypeIs(TYP_VOID));

    GenTree* op1 = tree->gtOp1;
    GenTree* op2 = tree->gtOp2;

    assert(!op1->isUsedFromMemory());
    assert(!op2->isUsedFromMemory());

    var_types op1Type = genActualType(op1->TypeGet());
    var_types op2Type = genActualType(op2->TypeGet());
    assert(genTypeSize(op1Type) == genTypeSize(op2Type));

    genConsumeOperands(tree);

    regNumber targetReg = tree->GetRegNum();
    assert(targetReg != REG_NA);

    if (varTypeIsFloating(op1Type))
    {
        assert(varTypeIsFloating(op2Type));

        GetEmitter()->emitIns_R_R(INS_fcmpu, emitActualTypeSize(op1Type), op1->GetRegNum(), op2->GetRegNum());

        genTreeOps oper     = tree->OperGet();
        bool       reversed = (tree->gtFlags & GTF_RELOP_NAN_UN) != 0;
        if (reversed)
        {
            oper = GenTree::ReverseRelop(oper);
        }

        BasicBlock* trueLabel = genCreateTempLabel();
        BasicBlock* doneLabel = genCreateTempLabel();

        instGen_Set_Reg_To_Imm(emitActualTypeSize(tree), targetReg, 0);
        ppcEmitBranchOnFloatRelop(GetEmitter(), oper, trueLabel);
        GetEmitter()->emitIns_J(INS_b, doneLabel);

        genDefineTempLabel(trueLabel);
        instGen_Set_Reg_To_Imm(emitActualTypeSize(tree), targetReg, 1);

        genDefineTempLabel(doneLabel);

        if (reversed)
        {
            GetEmitter()->emitIns_R_R_I(INS_xori, emitActualTypeSize(tree), targetReg, targetReg, 1);
        }

        genProduceReg(tree);
        return;
    }

    assert(varTypeIsIntegralOrI(op1Type));

    emitAttr     cmpSize   = ppcNormalizeCompareSize(emitActualTypeSize(op1Type));
    GenCondition cond      = GenCondition::FromIntegralRelop(tree);
    instruction  cmp       = ppcCompareInsForCondition(cond, cmpSize);

    GetEmitter()->emitIns_R_R(cmp, cmpSize, op1->GetRegNum(), op2->GetRegNum());

    BasicBlock* doneLabel = genCreateTempLabel();

    instGen_Set_Reg_To_Imm(emitActualTypeSize(tree), targetReg, 0);
    GetEmitter()->emitIns_J(ppcBranchInsForCondition(GenCondition::Reverse(cond)), doneLabel);
    instGen_Set_Reg_To_Imm(emitActualTypeSize(tree), targetReg, 1);

    genDefineTempLabel(doneLabel);
    genProduceReg(tree);
}

void CodeGen::genCodeForLclVar(GenTreeLclVar* tree)
{
    unsigned varNum = tree->GetLclNum();
    assert(varNum < m_compiler->lvaCount);

    LclVarDsc* varDsc = m_compiler->lvaGetDesc(varNum);
    assert((tree->gtFlags & GTF_VAR_DEF) == 0);

    if (!varDsc->lvIsRegCandidate() && !tree->IsMultiReg() && ((tree->gtFlags & GTF_SPILLED) == 0))
    {
        var_types targetType = varDsc->GetRegisterType(tree);
        assert(targetType != TYP_STRUCT);

        instruction loadIns = ins_Load(targetType);
        regNumber   baseReg = REG_NA;
        int         offset  = ppcGetLclFrameOffset(m_compiler, tree, &baseReg);
        regNumber   tmpReg  = ppcOffsetFitsInstruction(loadIns, offset) ? REG_NA : internalRegisters.GetSingle(tree);

        genInstrWithConstant(loadIns, emitTypeSize(targetType), tree->GetRegNum(), baseReg, offset, tmpReg);
        ppcEmitSignExtendSmallLoadIfNeeded(GetEmitter(), targetType, tree->GetRegNum());
        genProduceReg(tree);
    }
}

void CodeGen::genCodeForLclFld(GenTreeLclFld* tree)
{
    assert(tree->OperIs(GT_LCL_FLD));
    NYI_IF(tree->TypeIs(TYP_STRUCT), "GT_LCL_FLD: struct load local field not supported");

    var_types targetType = tree->TypeGet();
    regNumber targetReg  = tree->GetRegNum();
    assert(targetReg != REG_NA);

    instruction loadIns = ins_Load(targetType);
    regNumber   baseReg = REG_NA;
    int         offset  = ppcGetLclFrameOffset(m_compiler, tree, &baseReg);
    regNumber   tmpReg  = ppcOffsetFitsInstruction(loadIns, offset) ? REG_NA : internalRegisters.GetSingle(tree);

    genInstrWithConstant(loadIns, emitTypeSize(targetType), targetReg, baseReg, offset, tmpReg);
    ppcEmitSignExtendSmallLoadIfNeeded(GetEmitter(), targetType, targetReg);
    genProduceReg(tree);
}

void CodeGen::genCodeForLclAddr(GenTreeLclFld* lclAddrNode)
{
    assert(lclAddrNode->OperIs(GT_LCL_ADDR));

    var_types targetType = lclAddrNode->TypeGet();
    assert((targetType == TYP_BYREF) || (targetType == TYP_I_IMPL));

    bool fpBased = false;
    int  offset  = m_compiler->lvaFrameAddress(lclAddrNode->GetLclNum(), &fpBased) + lclAddrNode->GetLclOffs();

    regNumber baseReg   = fpBased ? REG_FPBASE : REG_SPBASE;
    regNumber targetReg = lclAddrNode->GetRegNum();
    assert(targetReg != REG_NA);

    if (emitter::isValidSimm16(offset))
    {
        GetEmitter()->emitIns_R_R_I(INS_addi, emitActualTypeSize(targetType), targetReg, baseReg, offset);
    }
    else
    {
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, targetReg, offset);
        GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, targetReg, baseReg, targetReg);
    }

    genProduceReg(lclAddrNode);
}

void CodeGen::genLeaInstruction(GenTreeAddrMode* lea)
{
    assert(lea->OperIs(GT_LEA));
    assert(lea->HasBase() || lea->HasIndex());

    genConsumeOperands(lea);

    emitAttr  size       = emitTypeSize(lea);
    int       offset     = lea->Offset();
    regNumber baseReg    = lea->HasBase() ? lea->Base()->GetRegNum() : REG_NA;
    regNumber indexReg   = lea->HasIndex() ? lea->Index()->GetRegNum() : REG_NA;
    regNumber targetReg  = lea->GetRegNum();
    unsigned  scale      = lea->HasIndex() ? lea->GetScale() : 0;
    regNumber addendReg  = indexReg;

    if (lea->HasIndex() && (scale > 1))
    {
        assert(isPow2(scale));
        unsigned shift = genLog2(scale);

        if (lea->HasBase())
        {
            addendReg = internalRegisters.GetSingle(lea);
        }
        else
        {
            addendReg = targetReg;
        }

        GetEmitter()->emitIns_R_R_I(INS_sldi, size, addendReg, indexReg, shift);
    }

    if (lea->HasBase() && lea->HasIndex())
    {
        GetEmitter()->emitIns_R_R_R(INS_add, size, targetReg, baseReg, addendReg);
    }
    else if (lea->HasBase())
    {
        if (emitter::isValidSimm16(offset))
        {
            if ((offset != 0) || (targetReg != baseReg))
            {
                GetEmitter()->emitIns_R_R_I(INS_addi, size, targetReg, baseReg, offset);
            }

            genProduceReg(lea);
            return;
        }

        regNumber tmpReg = internalRegisters.GetSingle(lea);
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, tmpReg, offset);
        GetEmitter()->emitIns_R_R_R(INS_add, size, targetReg, baseReg, tmpReg);

        genProduceReg(lea);
        return;
    }
    else
    {
        assert(lea->HasIndex());
        if ((scale <= 1) && (targetReg != indexReg))
        {
            GetEmitter()->emitIns_R_R_I(INS_addi, size, targetReg, indexReg, 0);
        }
    }

    if (offset != 0)
    {
        if (emitter::isValidSimm16(offset))
        {
            GetEmitter()->emitIns_R_R_I(INS_addi, size, targetReg, targetReg, offset);
        }
        else
        {
            regNumber tmpReg = internalRegisters.GetSingle(lea);
            instGen_Set_Reg_To_Imm(EA_PTRSIZE, tmpReg, offset);
            GetEmitter()->emitIns_R_R_R(INS_add, size, targetReg, targetReg, tmpReg);
        }
    }

    genProduceReg(lea);
}

//------------------------------------------------------------------------
// genCodeForIndexAddr: Produce code for a GT_INDEX_ADDR node.
//
// Arguments:
//    node - the GT_INDEX_ADDR node
//
void CodeGen::genCodeForIndexAddr(GenTreeIndexAddr* node)
{
    GenTree* const base  = node->Arr();
    GenTree* const index = node->Index();

    regNumber baseReg  = genConsumeReg(base);
    regNumber indexReg = genConsumeReg(index);

    gcInfo.gcMarkRegPtrVal(baseReg, base->TypeGet());
    assert(!varTypeIsGC(index->TypeGet()));
    assert(index->isUsedFromReg());

    regNumber tempReg = internalRegisters.GetSingle(node);

    if (node->IsBoundsChecked())
    {
        GetEmitter()->emitIns_R_R_I(INS_lwz, EA_4BYTE, tempReg, baseReg, node->gtLenOffset);

        instruction cmpIns = (genActualType(index) == TYP_INT) ? INS_cmplw : INS_cmpld;
        GetEmitter()->emitIns_R_R(cmpIns, EA_PTRSIZE, indexReg, tempReg);

        if (m_compiler->fgUseThrowHelperBlocks())
        {
            Compiler::AddCodeDsc* add = m_compiler->fgGetExcptnTarget(SCK_RNGCHK_FAIL, m_compiler->compCurBB);
            assert((add != nullptr) && "failed to find range check throw block");
            assert(add->acdUsed);

            GetEmitter()->emitIns_J(INS_bge, add->acdDstBlk);
        }
        else
        {
            BasicBlock* skipLabel = genCreateTempLabel();
            GetEmitter()->emitIns_J(INS_blt, skipLabel);

            genEmitHelperCall(m_compiler->acdHelper(SCK_RNGCHK_FAIL), 0, EA_UNKNOWN);

            genDefineTempLabel(skipLabel);
        }
    }

    regNumber indexForAddrReg = indexReg;
    if (genActualType(index) == TYP_INT)
    {
        GetEmitter()->emitIns_R_R_I(INS_clrldi, EA_PTRSIZE, tempReg, indexReg, 32);
        indexForAddrReg = tempReg;
    }

    regNumber targetReg  = node->GetRegNum();
    emitAttr  targetAttr = emitActualTypeSize(node);

    if (isPow2(node->gtElemSize))
    {
        unsigned scale = genLog2(node->gtElemSize);
        if (scale == 0)
        {
            GetEmitter()->emitIns_R_R_R(INS_add, targetAttr, targetReg, baseReg, indexForAddrReg);
        }
        else
        {
            GetEmitter()->emitIns_R_R_I(INS_sldi, EA_PTRSIZE, tempReg, indexForAddrReg, scale);
            GetEmitter()->emitIns_R_R_R(INS_add, targetAttr, targetReg, baseReg, tempReg);
        }
    }
    else
    {
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_R0, static_cast<ssize_t>(node->gtElemSize));
        GetEmitter()->emitIns_R_R_R(INS_mulld, EA_PTRSIZE, tempReg, indexForAddrReg, REG_R0);
        GetEmitter()->emitIns_R_R_R(INS_add, targetAttr, targetReg, baseReg, tempReg);
    }

    if (node->gtElemOffset != 0)
    {
        if (emitter::isValidSimm16(node->gtElemOffset))
        {
            GetEmitter()->emitIns_R_R_I(INS_addi, targetAttr, targetReg, targetReg, node->gtElemOffset);
        }
        else
        {
            instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_R0, node->gtElemOffset);
            GetEmitter()->emitIns_R_R_R(INS_add, targetAttr, targetReg, targetReg, REG_R0);
        }
    }

    gcInfo.gcMarkRegSetNpt(base->gtGetRegMask());

    genProduceReg(node);
}

void CodeGen::genCodeForStoreLclFld(GenTreeLclFld* tree)
{
    NYI_IF(tree->TypeIs(TYP_STRUCT), "GT_STORE_LCL_FLD: struct store local field not supported");

    GenTree* data = tree->gtOp1;
    genConsumeRegs(data);

    var_types targetType = tree->TypeGet();
    regNumber dataReg    = REG_NA;

    if (data->isContained())
    {
        assert(data->OperIs(GT_CNS_INT));
        assert(data->AsIntConCommon()->IconValue() == 0);
        dataReg = REG_R0;
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, dataReg, 0);
    }
    else
    {
        dataReg = data->GetRegNum();
    }

    assert(dataReg != REG_NA);

    instruction storeIns = ins_StoreFromSrc(dataReg, targetType);
    emitAttr    attr     = emitTypeSize(targetType);
    if (ppcLclOffsetFitsInstruction(m_compiler, storeIns, tree->GetLclNum(), tree->GetLclOffs()))
    {
        GetEmitter()->emitIns_S_R(storeIns, attr, dataReg, tree->GetLclNum(), tree->GetLclOffs());
    }
    else
    {
        regNumber baseReg = REG_NA;
        int       offset  = ppcGetLclFrameOffset(m_compiler, tree, &baseReg);
        regNumber tmpReg  = internalRegisters.GetSingle(tree);

        genInstrWithConstant(storeIns, attr, dataReg, baseReg, offset, tmpReg);
    }

    genUpdateLife(tree);
    m_compiler->lvaGetDesc(tree->GetLclNum())->SetRegNum(REG_STK);
}

void CodeGen::genCodeForStoreLclVar(GenTreeLclVar* lclNode)
{
    GenTree* data = lclNode->gtOp1;

    if (data->gtSkipReloadOrCopy()->IsMultiRegNode())
    {
        genMultiRegStoreToLocal(lclNode);
        return;
    }

    if (lclNode->IsMultiReg())
    {
        NYI_POWERPC64("multi-reg local store");
    }

    LclVarDsc* varDsc     = m_compiler->lvaGetDesc(lclNode);
    regNumber  targetReg  = lclNode->GetRegNum();
    var_types  targetType = varDsc->GetRegisterType(lclNode);

    genConsumeRegs(data);

    regNumber dataReg = REG_NA;

    if (data->isContained())
    {
        assert(data->OperIs(GT_CNS_INT));
        assert(data->AsIntConCommon()->IconValue() == 0);

        if (targetReg != REG_NA)
        {
            instGen_Set_Reg_To_Imm(emitActualTypeSize(targetType), targetReg, 0);
            genProduceReg(lclNode);
            return;
        }

        dataReg = REG_R0;
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, dataReg, 0);
    }
    else
    {
        dataReg = data->GetRegNum();
    }

    assert(dataReg != REG_NA);

    if (targetReg == REG_NA)
    {
        inst_set_SV_var(lclNode);

        instruction storeIns = ins_StoreFromSrc(dataReg, targetType);
        emitAttr    attr     = varTypeIsGC(data) ? emitTypeSize(data) : emitActualTypeSize(targetType);
        if (ppcLclOffsetFitsInstruction(m_compiler, storeIns, lclNode->GetLclNum(), lclNode->GetLclOffs()))
        {
            GetEmitter()->emitIns_S_R(storeIns, attr, dataReg, lclNode->GetLclNum(), lclNode->GetLclOffs());
        }
        else
        {
            regNumber baseReg = REG_NA;
            int       offset  = ppcGetLclFrameOffset(m_compiler, lclNode, &baseReg);
            regNumber tmpReg  = internalRegisters.GetSingle(lclNode);

            genInstrWithConstant(storeIns, attr, dataReg, baseReg, offset, tmpReg);
        }

        if (varTypeIsGC(targetType) && data->OperIsLocalRead() &&
            (data->AsLclVarCommon()->GetLclNum() == lclNode->GetLclNum()) && (varDsc->GetRegNum() == dataReg))
        {
            // The local's home is moving from its incoming register to its stack slot.
            // Stop reporting the old register before future call safe points.
            gcInfo.gcMarkRegSetNpt(genRegMask(dataReg));
        }

        genUpdateLife(lclNode);
        varDsc->SetRegNum(REG_STK);
    }
    else
    {
        GetEmitter()->emitIns_Mov(emitActualTypeSize(targetType), targetReg, dataReg, true);
        genProduceReg(lclNode);
    }
}

void CodeGen::genCodeForIndir(GenTreeIndir* tree)
{
    assert(tree->OperIs(GT_IND));
    NYI_IF(tree->TypeIs(TYP_STRUCT), "GT_IND: struct load not supported");

    GenTree* addr = tree->Addr();
    assert(!addr->isContained());

    ssize_t    offset     = tree->Offset();
    regNumber  baseReg    = genConsumeReg(addr);
    var_types  targetType = tree->TypeGet();
    regNumber  targetReg  = tree->GetRegNum();
    instruction loadIns    = ins_Load(targetType);

    if (!ppcOffsetFitsInstruction(loadIns, offset))
    {
        regNumber tempReg = internalRegisters.GetSingle(tree);
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, tempReg, offset);
        GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, tempReg, baseReg, tempReg);
        baseReg = tempReg;
        offset  = 0;
    }

    if ((tree->gtFlags & GTF_IND_VOLATILE) != 0)
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }

    GetEmitter()->emitIns_R_AR(loadIns, emitActualTypeSize(targetType), targetReg, baseReg, static_cast<int>(offset));
    ppcEmitSignExtendSmallLoadIfNeeded(GetEmitter(), targetType, targetReg);

    if ((tree->gtFlags & GTF_IND_VOLATILE) != 0)
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }

    genProduceReg(tree);
}

void CodeGen::genCodeForNullCheck(GenTreeIndir* tree)
{
    assert(tree->OperIs(GT_NULLCHECK));

    GenTree* addr = tree->Addr();
    assert(!addr->isContained());

    ssize_t    offset  = tree->Offset();
    regNumber  baseReg = genConsumeReg(addr);
    instruction loadIns = ins_Load(tree->TypeGet());

    if (!ppcOffsetFitsInstruction(loadIns, offset))
    {
        regNumber tempReg = internalRegisters.GetSingle(tree);
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, tempReg, offset);
        GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, tempReg, baseReg, tempReg);
        baseReg = tempReg;
        offset  = 0;
    }

    GetEmitter()->emitIns_R_AR(loadIns, emitActualTypeSize(tree), REG_R0, baseReg, static_cast<int>(offset));
}

//---------------------------------------------------------------------
// genCodeForPhysReg - generate code for a GT_PHYSREG node
//
// Arguments
//    tree - the GT_PHYSREG node
//
// Return value:
//    None
//
void CodeGen::genCodeForPhysReg(GenTreePhysReg* tree)
{
    assert(tree->OperIs(GT_PHYSREG));

    var_types targetType = tree->TypeGet();
    regNumber targetReg = tree->GetRegNum();
    if (targetReg != tree->gtSrcReg)
    {
        GetEmitter()->emitIns_Mov(emitActualTypeSize(targetType), targetReg, tree->gtSrcReg, /* canSkip */ true);
        genTransferRegGCState(targetReg, tree->gtSrcReg);
    }

    genProduceReg(tree);
}

void CodeGen::genCodeForStoreInd(GenTreeStoreInd* tree)
{
    NYI_IF(tree->TypeIs(TYP_STRUCT), "GT_STOREIND: struct store not supported");

    GenTree* addr = tree->Addr();
    GenTree* data = tree->Data();
    assert(!addr->isContained());

    GCInfo::WriteBarrierForm writeBarrierForm = gcInfo.gcIsWriteBarrierCandidate(tree);
    if (writeBarrierForm != GCInfo::WBF_NoBarrier)
    {
        if ((tree->gtFlags & GTF_IND_VOLATILE) != 0)
        {
            instGen_MemoryBarrier(BARRIER_FULL);
        }

        genConsumeOperands(tree);

        noway_assert(data->GetRegNum() != REG_WRITE_BARRIER_DST);

        genCopyRegIfNeeded(addr, REG_WRITE_BARRIER_DST);
        genCopyRegIfNeeded(data, REG_WRITE_BARRIER_SRC);

        ssize_t offset = tree->Offset();
        if (offset != 0)
        {
            if (emitter::isValidSimm16(offset))
            {
                GetEmitter()->emitIns_R_R_I(INS_addi, EA_PTRSIZE, REG_WRITE_BARRIER_DST, REG_WRITE_BARRIER_DST,
                                            offset);
            }
            else
            {
                instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_R0, offset);
                GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, REG_WRITE_BARRIER_DST, REG_WRITE_BARRIER_DST,
                                            REG_R0);
            }
        }

        genGCWriteBarrier(tree, writeBarrierForm);

        if ((tree->gtFlags & GTF_IND_VOLATILE) != 0)
        {
            instGen_MemoryBarrier(BARRIER_FULL);
        }

        return;
    }

    ssize_t   offset  = tree->Offset();
    regNumber baseReg = genConsumeReg(addr);
    var_types type    = tree->TypeGet();
    instruction storeIns = ins_Store(type);

    if (!ppcOffsetFitsInstruction(storeIns, offset))
    {
        regNumber tempReg = internalRegisters.GetSingle(tree);
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, tempReg, offset);
        GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, tempReg, baseReg, tempReg);
        baseReg = tempReg;
        offset  = 0;
    }

    genConsumeRegs(data);

    regNumber dataReg = REG_NA;
    if (data->isContained())
    {
        assert(data->OperIs(GT_CNS_INT));
        assert(data->AsIntConCommon()->IconValue() == 0);
        dataReg = REG_R0;
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, dataReg, 0);
    }
    else
    {
        dataReg = data->GetRegNum();
    }

    assert(dataReg != REG_NA);
    storeIns = ins_StoreFromSrc(dataReg, type);

    if ((tree->gtFlags & GTF_IND_VOLATILE) != 0)
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }

    GetEmitter()->emitIns_AR_R(storeIns, emitActualTypeSize(type), dataReg, baseReg, static_cast<int>(offset));

    if ((tree->gtFlags & GTF_IND_VOLATILE) != 0)
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }
}

//------------------------------------------------------------------------
// genCodeForStoreBlk: Produce code for a GT_STORE_BLK node.
//
// Arguments:
//    blkOp - the block store node
//
void CodeGen::genCodeForStoreBlk(GenTreeBlk* blkOp)
{
    assert(blkOp->OperIs(GT_STORE_BLK));

    if (blkOp->gtBlkOpGcUnsafe)
    {
        GetEmitter()->emitDisableGC();
    }

    bool isCopyBlk = blkOp->OperIsCopyBlkOp();

    switch (blkOp->gtBlkOpKind)
    {
        case GenTreeBlk::BlkOpKindCpObjUnroll:
            genCodeForCpObj(blkOp->AsBlk());
            break;

        case GenTreeBlk::BlkOpKindLoop:
            assert(!isCopyBlk);
            genCodeForInitBlkLoop(blkOp);
            break;

        case GenTreeBlk::BlkOpKindUnroll:
            if (isCopyBlk)
            {
                genCodeForCpBlkUnroll(blkOp);
            }
            else
            {
                genCodeForInitBlkUnroll(blkOp);
            }
            break;

        default:
            unreached();
    }

    if (blkOp->gtBlkOpGcUnsafe)
    {
        GetEmitter()->emitEnableGC();
    }
}

//------------------------------------------------------------------------
// genCodeForInitBlkUnroll: Produce code for an unrolled initblk.
//
// Arguments:
//    node - the block store node
//
void CodeGen::genCodeForInitBlkUnroll(GenTreeBlk* node)
{
    assert(node->OperIs(GT_STORE_BLK));

    unsigned  dstLclNum      = BAD_VAR_NUM;
    regNumber dstAddrBaseReg = REG_NA;
    int       dstOffset      = 0;
    GenTree*  dstAddr        = node->Addr();

    if (!dstAddr->isContained())
    {
        dstAddrBaseReg = genConsumeReg(dstAddr);
    }
    else if (dstAddr->OperIsAddrMode())
    {
        assert(!dstAddr->AsAddrMode()->HasIndex());

        dstAddrBaseReg = genConsumeReg(dstAddr->AsAddrMode()->Base());
        dstOffset      = dstAddr->AsAddrMode()->Offset();
    }
    else
    {
        assert(dstAddr->OperIs(GT_LCL_ADDR));
        dstLclNum = dstAddr->AsLclVarCommon()->GetLclNum();
        dstOffset = dstAddr->AsLclVarCommon()->GetLclOffs();
    }

    regNumber srcReg = REG_NA;
    GenTree*  src    = node->Data();

    if (src->OperIs(GT_INIT_VAL))
    {
        assert(src->isContained());
        src = src->gtGetOp1();
    }

    if (!src->isContained())
    {
        srcReg = genConsumeReg(src);
    }
    else
    {
        assert(src->IsIntegralConst(0));
        srcReg = REG_R0;
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, srcReg, 0);
    }

    if (node->IsVolatile())
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }

    unsigned size = node->GetLayout()->GetSize();

    assert(size <= INT32_MAX);
    assert(dstOffset < INT32_MAX - static_cast<int>(size));

    regNumber dstTmpReg = dstAddr->isContained() ? internalRegisters.GetSingle(node) : REG_NA;
    auto emitStore = [=](instruction storeIns, emitAttr attr, regNumber dataReg, int storeOffset) {
        if (dstLclNum != BAD_VAR_NUM)
        {
            regNumber baseReg     = REG_NA;
            int       frameOffset = ppcGetLclFrameOffset(m_compiler, dstLclNum, storeOffset, &baseReg);
            genInstrWithConstant(storeIns, attr, dataReg, baseReg, frameOffset, dstTmpReg);
        }
        else
        {
            genInstrWithConstant(storeIns, attr, dataReg, dstAddrBaseReg, storeOffset, dstTmpReg);
        }
    };

    for (unsigned regSize = 2 * REGSIZE_BYTES; size >= regSize; size -= regSize, dstOffset += regSize)
    {
        emitStore(INS_std, EA_8BYTE, srcReg, dstOffset);
        emitStore(INS_std, EA_8BYTE, srcReg, dstOffset + 8);
    }

    for (unsigned regSize = REGSIZE_BYTES; size > 0; size -= regSize, dstOffset += regSize)
    {
        while (regSize > size)
        {
            regSize /= 2;
        }

        instruction storeIns;
        emitAttr    attr = EA_ATTR(regSize);

        switch (regSize)
        {
            case 1:
                storeIns = INS_stb;
                break;
            case 2:
                storeIns = INS_sth;
                break;
            case 4:
                storeIns = INS_stw;
                break;
            case 8:
                storeIns = INS_std;
                break;
            default:
                unreached();
        }

        emitStore(storeIns, attr, srcReg, dstOffset);
    }
}

//------------------------------------------------------------------------
// genCodeForCpObj: Produce code for a CpObj block store with GC pointers.
//
// Arguments:
//    cpObjNode - the block store node
//
void CodeGen::genCodeForCpObj(GenTreeBlk* cpObjNode)
{
    GenTree*  dstAddr     = cpObjNode->Addr();
    GenTree*  source      = cpObjNode->Data();
    var_types srcAddrType = TYP_BYREF;
    unsigned  dstLclNum   = BAD_VAR_NUM;
    unsigned  dstLclOffs  = 0;

    assert(source->isContained());
    if (source->OperIs(GT_IND))
    {
        GenTree* srcAddr = source->gtGetOp1();
        assert(!srcAddr->isContained());
        srcAddrType = srcAddr->TypeGet();
    }
    else
    {
        noway_assert(source->IsLocal());
    }

    bool dstOnStack = cpObjNode->IsAddressNotOnHeap(m_compiler);
    if (dstOnStack && dstAddr->OperIs(GT_LCL_ADDR))
    {
        dstLclNum  = dstAddr->AsLclVarCommon()->GetLclNum();
        dstLclOffs = dstAddr->AsLclVarCommon()->GetLclOffs();
    }

#ifdef DEBUG
    assert(!dstAddr->isContained());
    assert(cpObjNode->GetLayout()->HasGCPtr());
#endif

    genConsumeBlockOp(cpObjNode, REG_WRITE_BARRIER_DST_BYREF, REG_WRITE_BARRIER_SRC_BYREF, REG_NA);
    gcInfo.gcMarkRegPtrVal(REG_WRITE_BARRIER_SRC_BYREF, srcAddrType);
    gcInfo.gcMarkRegPtrVal(REG_WRITE_BARRIER_DST_BYREF, dstAddr->TypeGet());

    ClassLayout* layout = cpObjNode->GetLayout();
    unsigned     slots  = layout->GetSlotCount();

    regNumber tmpReg  = internalRegisters.Extract(cpObjNode);
    regNumber tmpReg2 = REG_NA;

    assert(genIsValidIntReg(tmpReg));
    assert(tmpReg != REG_WRITE_BARRIER_SRC_BYREF);
    assert(tmpReg != REG_WRITE_BARRIER_DST_BYREF);

    if (slots > 1)
    {
        tmpReg2 = internalRegisters.GetSingle(cpObjNode);
        assert(tmpReg2 != tmpReg);
        assert(genIsValidIntReg(tmpReg2));
        assert(tmpReg2 != REG_WRITE_BARRIER_DST_BYREF);
        assert(tmpReg2 != REG_WRITE_BARRIER_SRC_BYREF);
    }

    if (cpObjNode->IsVolatile())
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }

    emitter* emit = GetEmitter();

    emitAttr attrSrcAddr = emitActualTypeSize(srcAddrType);
    emitAttr attrDstAddr = emitActualTypeSize(dstAddr->TypeGet());

    if (dstOnStack)
    {
        auto emitStackStore = [this, emit, dstLclNum, dstLclOffs](instruction storeIns,
                                                                  emitAttr    attr,
                                                                  regNumber   dataReg,
                                                                  unsigned    lclStoreOffset,
                                                                  unsigned    regStoreOffset) {
            if ((dstLclNum != BAD_VAR_NUM) &&
                ppcLclOffsetFitsInstruction(m_compiler, storeIns, dstLclNum, dstLclOffs + lclStoreOffset))
            {
                emit->emitIns_S_R(storeIns, attr, dataReg, dstLclNum, dstLclOffs + lclStoreOffset);
            }
            else
            {
                // REG_WRITE_BARRIER_DST_BYREF is post-incremented as the copy proceeds,
                // so fallback stores must use offsets relative to the current pair.
                emit->emitIns_R_R_I(storeIns, attr, dataReg, REG_WRITE_BARRIER_DST_BYREF, regStoreOffset);
            }
        };

        unsigned i = 0;
        while (i < slots - 1)
        {
            emitAttr attr0 = emitTypeSize(layout->GetGCPtrType(i + 0));
            emitAttr attr1 = emitTypeSize(layout->GetGCPtrType(i + 1));
            if ((i + 2) == slots)
            {
                attrSrcAddr = EA_8BYTE;
                attrDstAddr = EA_8BYTE;
            }

            emit->emitIns_R_R_I(INS_ld, attr0, tmpReg, REG_WRITE_BARRIER_SRC_BYREF, 0);
            emit->emitIns_R_R_I(INS_ld, attr1, tmpReg2, REG_WRITE_BARRIER_SRC_BYREF, TARGET_POINTER_SIZE);
            emit->emitIns_R_R_I(INS_addi, attrSrcAddr, REG_WRITE_BARRIER_SRC_BYREF, REG_WRITE_BARRIER_SRC_BYREF,
                                2 * TARGET_POINTER_SIZE);
            emitStackStore(INS_std, attr0, tmpReg, i * TARGET_POINTER_SIZE, 0);
            emitStackStore(INS_std, attr1, tmpReg2, (i + 1) * TARGET_POINTER_SIZE, TARGET_POINTER_SIZE);
            emit->emitIns_R_R_I(INS_addi, attrDstAddr, REG_WRITE_BARRIER_DST_BYREF, REG_WRITE_BARRIER_DST_BYREF,
                                2 * TARGET_POINTER_SIZE);
            i += 2;
        }

        if (i < slots)
        {
            emitAttr attr0 = emitTypeSize(layout->GetGCPtrType(i));
            if (i + 1 >= slots)
            {
                attrSrcAddr = EA_8BYTE;
                attrDstAddr = EA_8BYTE;
            }

            emit->emitIns_R_R_I(INS_ld, attr0, tmpReg, REG_WRITE_BARRIER_SRC_BYREF, 0);
            emit->emitIns_R_R_I(INS_addi, attrSrcAddr, REG_WRITE_BARRIER_SRC_BYREF, REG_WRITE_BARRIER_SRC_BYREF,
                                TARGET_POINTER_SIZE);
            emitStackStore(INS_std, attr0, tmpReg, i * TARGET_POINTER_SIZE, 0);
            emit->emitIns_R_R_I(INS_addi, attrDstAddr, REG_WRITE_BARRIER_DST_BYREF, REG_WRITE_BARRIER_DST_BYREF,
                                TARGET_POINTER_SIZE);
        }
    }
    else
    {
        unsigned gcPtrCount = cpObjNode->GetLayout()->GetGCPtrCount();

        unsigned i = 0;
        while (i < slots)
        {
            if (!layout->IsGCPtr(i))
            {
                if ((i + 1 < slots) && !layout->IsGCPtr(i + 1))
                {
                    if ((i + 2) == slots)
                    {
                        attrSrcAddr = EA_8BYTE;
                        attrDstAddr = EA_8BYTE;
                    }

                    emit->emitIns_R_R_I(INS_ld, EA_8BYTE, tmpReg, REG_WRITE_BARRIER_SRC_BYREF, 0);
                    emit->emitIns_R_R_I(INS_ld, EA_8BYTE, tmpReg2, REG_WRITE_BARRIER_SRC_BYREF, TARGET_POINTER_SIZE);
                    emit->emitIns_R_R_I(INS_addi, attrSrcAddr, REG_WRITE_BARRIER_SRC_BYREF,
                                        REG_WRITE_BARRIER_SRC_BYREF, 2 * TARGET_POINTER_SIZE);
                    emit->emitIns_R_R_I(INS_std, EA_8BYTE, tmpReg, REG_WRITE_BARRIER_DST_BYREF, 0);
                    emit->emitIns_R_R_I(INS_std, EA_8BYTE, tmpReg2, REG_WRITE_BARRIER_DST_BYREF, TARGET_POINTER_SIZE);
                    emit->emitIns_R_R_I(INS_addi, attrDstAddr, REG_WRITE_BARRIER_DST_BYREF,
                                        REG_WRITE_BARRIER_DST_BYREF, 2 * TARGET_POINTER_SIZE);
                    ++i;
                }
                else
                {
                    if (i + 1 >= slots)
                    {
                        attrSrcAddr = EA_8BYTE;
                        attrDstAddr = EA_8BYTE;
                    }

                    emit->emitIns_R_R_I(INS_ld, EA_8BYTE, tmpReg, REG_WRITE_BARRIER_SRC_BYREF, 0);
                    emit->emitIns_R_R_I(INS_addi, attrSrcAddr, REG_WRITE_BARRIER_SRC_BYREF,
                                        REG_WRITE_BARRIER_SRC_BYREF, TARGET_POINTER_SIZE);
                    emit->emitIns_R_R_I(INS_std, EA_8BYTE, tmpReg, REG_WRITE_BARRIER_DST_BYREF, 0);
                    emit->emitIns_R_R_I(INS_addi, attrDstAddr, REG_WRITE_BARRIER_DST_BYREF,
                                        REG_WRITE_BARRIER_DST_BYREF, TARGET_POINTER_SIZE);
                }
            }
            else
            {
                genEmitHelperCall(CORINFO_HELP_ASSIGN_BYREF, 0, EA_PTRSIZE);
                gcPtrCount--;
            }
            ++i;
        }
        assert(gcPtrCount == 0);
    }

    if (cpObjNode->IsVolatile())
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }

    gcInfo.gcMarkRegSetNpt(RBM_WRITE_BARRIER_SRC_BYREF | RBM_WRITE_BARRIER_DST_BYREF);
}

//------------------------------------------------------------------------
// genCodeForCpBlkUnroll: Produce code for an unrolled cpblk.
//
// Arguments:
//    cpBlkNode - the block store node
//
void CodeGen::genCodeForCpBlkUnroll(GenTreeBlk* cpBlkNode)
{
    assert(cpBlkNode->OperIs(GT_STORE_BLK));

    unsigned  dstLclNum      = BAD_VAR_NUM;
    regNumber dstAddrBaseReg = REG_NA;
    int       dstOffset      = 0;
    GenTree*  dstAddr        = cpBlkNode->Addr();

    if (!dstAddr->isContained())
    {
        dstAddrBaseReg = genConsumeReg(dstAddr);
    }
    else if (dstAddr->OperIsAddrMode())
    {
        assert(!dstAddr->AsAddrMode()->HasIndex());

        dstAddrBaseReg = genConsumeReg(dstAddr->AsAddrMode()->Base());
        dstOffset      = dstAddr->AsAddrMode()->Offset();
    }
    else
    {
        assert(dstAddr->OperIs(GT_LCL_ADDR));
        dstLclNum = dstAddr->AsLclVarCommon()->GetLclNum();
        dstOffset = dstAddr->AsLclVarCommon()->GetLclOffs();
    }

    unsigned  srcLclNum      = BAD_VAR_NUM;
    regNumber srcAddrBaseReg = REG_NA;
    int       srcOffset      = 0;
    GenTree*  src            = cpBlkNode->Data();

    assert(src->isContained());

    if (src->OperIs(GT_LCL_VAR, GT_LCL_FLD))
    {
        srcLclNum = src->AsLclVarCommon()->GetLclNum();
        srcOffset = src->AsLclVarCommon()->GetLclOffs();
    }
    else
    {
        assert(src->OperIs(GT_IND));
        GenTree* srcAddr = src->AsIndir()->Addr();

        if (!srcAddr->isContained())
        {
            srcAddrBaseReg = genConsumeReg(srcAddr);
        }
        else if (srcAddr->OperIsAddrMode())
        {
            srcAddrBaseReg = genConsumeReg(srcAddr->AsAddrMode()->Base());
            srcOffset      = srcAddr->AsAddrMode()->Offset();
        }
        else
        {
            assert(srcAddr->OperIs(GT_LCL_ADDR));
            srcLclNum = srcAddr->AsLclVarCommon()->GetLclNum();
            srcOffset = srcAddr->AsLclVarCommon()->GetLclOffs();
        }
    }

    if (cpBlkNode->IsVolatile())
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }

    unsigned size      = cpBlkNode->GetLayout()->GetSize();
    unsigned totalSize = size;

    assert(size <= INT32_MAX);
    assert(srcOffset < INT32_MAX - static_cast<int>(size));
    assert(dstOffset < INT32_MAX - static_cast<int>(size));

    regNumber tempReg = internalRegisters.Extract(cpBlkNode, RBM_ALLINT);
    regNumber tempReg2 = REG_NA;

    if (size >= 2 * REGSIZE_BYTES)
    {
        tempReg2 = internalRegisters.Extract(cpBlkNode, RBM_ALLINT);
    }

    bool containedDstNeedsLargeOffsetTemp = false;
    if (dstAddr->isContained())
    {
        int initialDstOffset = dstOffset;
        if (dstLclNum != BAD_VAR_NUM)
        {
            regNumber baseReg = REG_NA;
            initialDstOffset  = ppcGetLclFrameOffset(m_compiler, dstLclNum, dstOffset, &baseReg);
        }

        containedDstNeedsLargeOffsetTemp = !ppcOffsetRangeFitsSimm16(initialDstOffset, totalSize) ||
                                           !ppcOffsetFitsInstruction(INS_std, initialDstOffset);
    }

    regNumber dstTmpReg = containedDstNeedsLargeOffsetTemp ? internalRegisters.Extract(cpBlkNode, RBM_ALLINT) : REG_NA;

    auto emitLoad = [this, srcLclNum, srcAddrBaseReg](instruction loadIns,
                                                      emitAttr    attr,
                                                      regNumber   targetReg,
                                                      int         loadOffset) {
        if (srcLclNum != BAD_VAR_NUM)
        {
            regNumber baseReg     = REG_NA;
            int       frameOffset = ppcGetLclFrameOffset(m_compiler, srcLclNum, loadOffset, &baseReg);
            genInstrWithConstant(loadIns, attr, targetReg, baseReg, frameOffset, targetReg);
        }
        else
        {
            genInstrWithConstant(loadIns, attr, targetReg, srcAddrBaseReg, loadOffset, targetReg);
        }
    };

    auto emitStore = [this, dstLclNum, dstAddrBaseReg, dstTmpReg](instruction storeIns,
                                                                  emitAttr    attr,
                                                                  regNumber   dataReg,
                                                                  int         storeOffset) {
        if (dstLclNum != BAD_VAR_NUM)
        {
            regNumber baseReg     = REG_NA;
            int       frameOffset = ppcGetLclFrameOffset(m_compiler, dstLclNum, storeOffset, &baseReg);
            genInstrWithConstant(storeIns, attr, dataReg, baseReg, frameOffset, dstTmpReg);
        }
        else
        {
            genInstrWithConstant(storeIns, attr, dataReg, dstAddrBaseReg, storeOffset, dstTmpReg);
        }
    };

    if (size >= 2 * REGSIZE_BYTES)
    {
        assert(tempReg2 != REG_NA);

        for (unsigned regSize = 2 * REGSIZE_BYTES; size >= regSize;
             size -= regSize, srcOffset += regSize, dstOffset += regSize)
        {
            emitLoad(INS_ld, EA_8BYTE, tempReg, srcOffset);
            emitLoad(INS_ld, EA_8BYTE, tempReg2, srcOffset + 8);
            emitStore(INS_std, EA_8BYTE, tempReg, dstOffset);
            emitStore(INS_std, EA_8BYTE, tempReg2, dstOffset + 8);
        }
    }

    for (unsigned regSize = REGSIZE_BYTES; size > 0; size -= regSize, srcOffset += regSize, dstOffset += regSize)
    {
        while (regSize > size)
        {
            regSize /= 2;
        }

        instruction loadIns;
        instruction storeIns;
        emitAttr    attr = EA_ATTR(regSize);

        switch (regSize)
        {
            case 1:
                loadIns  = INS_lbz;
                storeIns = INS_stb;
                break;
            case 2:
                loadIns  = INS_lhz;
                storeIns = INS_sth;
                break;
            case 4:
                loadIns  = INS_lwz;
                storeIns = INS_stw;
                break;
            case 8:
                loadIns  = INS_ld;
                storeIns = INS_std;
                break;
            default:
                unreached();
        }

        emitLoad(loadIns, attr, tempReg, srcOffset);
        emitStore(storeIns, attr, tempReg, dstOffset);
    }

    if (cpBlkNode->IsVolatile())
    {
        instGen_MemoryBarrier(BARRIER_LOAD_ONLY);
    }
}

//------------------------------------------------------------------------
// genCodeForInitBlkLoop: Produce code for a zeroing initblk loop.
//
// Arguments:
//    initBlkNode - the block store node
//
void CodeGen::genCodeForInitBlkLoop(GenTreeBlk* initBlkNode)
{
    GenTree* const dstNode = initBlkNode->Addr();
    genConsumeReg(dstNode);
    const regNumber dstReg = dstNode->GetRegNum();

    GenTree* src = initBlkNode->Data();
    if (src->OperIs(GT_INIT_VAL))
    {
        assert(src->isContained());
        src = src->gtGetOp1();
    }

    regNumber fillReg = REG_NA;
    if (!src->isContained())
    {
        fillReg = genConsumeReg(src);
    }
    else
    {
        assert(src->IsIntegralConst(0));
        fillReg = REG_R0;
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, fillReg, 0);
    }

    if (initBlkNode->IsVolatile())
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }

    const unsigned size = initBlkNode->GetLayout()->GetSize();
    assert((size >= TARGET_POINTER_SIZE) && ((size % TARGET_POINTER_SIZE) == 0));

    GetEmitter()->emitIns_R_R_I(INS_std, EA_PTRSIZE, fillReg, dstReg, 0);
    if (size > TARGET_POINTER_SIZE)
    {
        gcInfo.gcMarkRegPtrVal(dstReg, dstNode->TypeGet());

        const regNumber tempReg = internalRegisters.GetSingle(initBlkNode);
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, tempReg, size - TARGET_POINTER_SIZE);

        // tempReg becomes an interior pointer below. Keep the whole lifetime of
        // that unreported absolute address in a no-GC region.
        GetEmitter()->emitDisableGC();
        GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, tempReg, dstReg, tempReg);

        BasicBlock* loop = genCreateTempLabel();
        genDefineTempLabel(loop);

        GetEmitter()->emitIns_R_R_I(INS_std, EA_PTRSIZE, fillReg, tempReg, 0);
        GetEmitter()->emitIns_R_R_I(INS_addi, EA_PTRSIZE, tempReg, tempReg, -static_cast<ssize_t>(TARGET_POINTER_SIZE));
        GetEmitter()->emitIns_R_R(INS_cmpd, EA_PTRSIZE, tempReg, dstReg);
        GetEmitter()->emitIns_J(INS_bne, loop);
        GetEmitter()->emitEnableGC();

        gcInfo.gcMarkRegSetNpt(genRegMask(dstReg));
    }
}

void CodeGen::genCodeForJumpCompare(GenTreeOpCC* tree)
{
    assert(m_compiler->compCurBB->KindIs(BBJ_COND));

    assert(tree->OperIs(GT_JCMP));
    assert(!varTypeIsFloating(tree));
    assert(tree->TypeIs(TYP_VOID));
    assert(tree->GetRegNum() == REG_NA);

    GenTree* op1 = tree->gtGetOp1();
    GenTree* op2 = tree->gtGetOp2();
    assert(!op1->isUsedFromMemory());
    assert(!op2->isUsedFromMemory());

    var_types op1Type = genActualType(op1->TypeGet());
    var_types op2Type = genActualType(op2->TypeGet());
    assert(genTypeSize(op1Type) == genTypeSize(op2Type));
    assert(varTypeIsIntegralOrI(op1Type));

    genConsumeOperands(tree);

    emitAttr  cmpSize = ppcNormalizeCompareSize(emitActualTypeSize(op1Type));
    regNumber regOp1  = op1->GetRegNum();
    regNumber regOp2  = op2->GetRegNum();

    GenCondition cond = tree->gtCondition;
    instruction  cmp  = ppcCompareInsForCondition(cond, cmpSize);
    GetEmitter()->emitIns_R_R(cmp, cmpSize, regOp1, regOp2);

    GetEmitter()->emitIns_J(ppcBranchInsForCondition(cond), m_compiler->compCurBB->GetTrueTarget());

    BasicBlock* falseTarget = m_compiler->compCurBB->GetFalseTarget();
    if (!m_compiler->compCurBB->CanRemoveJumpToTarget(falseTarget, m_compiler))
    {
        inst_JMP(EJ_jmp, falseTarget);
    }
}

void CodeGen::genAsyncResumeInfo(GenTreeVal* treeNode)
{
    emitAttr attr = EA_PTRSIZE;
    if (m_compiler->eeDataWithCodePointersNeedsRelocs())
    {
        attr = EA_SET_FLG(EA_PTRSIZE, EA_CNS_RELOC_FLG);
    }

    GetEmitter()->emitIns_R_C(INS_addi, attr, treeNode->GetRegNum(), REG_NA,
                              genEmitAsyncResumeInfo(static_cast<unsigned>(treeNode->gtVal1)));
    genProduceReg(treeNode);
}

void CodeGen::genFtnEntry(GenTree* treeNode)
{
    GetEmitter()->emitIns_R_L(INS_addi, EA_PTRSIZE, GetEmitter()->emitPrologIG, treeNode->GetRegNum());
    genProduceReg(treeNode);
}

void CodeGen::genNonLocalJmp(GenTreeUnOp* tree)
{
    SetHasTailCalls(true);

    genConsumeOperands(tree->AsOp());
    regNumber targetReg = tree->gtGetOp1()->GetRegNum();

    GetEmitter()->emitIns_R_R(INS_mtctr, EA_PTRSIZE, targetReg, targetReg);
    GetEmitter()->emitIns(INS_bctr);
}

// generate code for a switch statement based on a table of ip-relative offsets
void CodeGen::genTableBasedSwitch(GenTree* treeNode)
{
    assert(m_compiler->compCurBB->KindIs(BBJ_SWITCH));

    genConsumeOperands(treeNode->AsOp());
    regNumber idxReg  = treeNode->AsOp()->gtOp1->GetRegNum();
    regNumber baseReg = treeNode->AsOp()->gtOp2->GetRegNum();

    regNumber tmpReg = internalRegisters.GetSingle(treeNode);

    GetEmitter()->emitIns_R_R_I(INS_sldi, EA_PTRSIZE, tmpReg, idxReg, 2);
    GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, baseReg, baseReg, tmpReg);
    GetEmitter()->emitIns_R_R_I(INS_lwa, EA_4BYTE, baseReg, baseReg, 0);

    GetEmitter()->emitIns_R_L(INS_addi, EA_PTRSIZE, m_compiler->fgFirstBB, tmpReg);
    GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, baseReg, baseReg, tmpReg);

    GetEmitter()->emitIns_R_R(INS_mtctr, EA_PTRSIZE, baseReg, baseReg);
    GetEmitter()->emitIns(INS_bctr);
}

// emits the table and an instruction to get the address of the first element
void CodeGen::genJumpTable(GenTree* treeNode)
{
    unsigned jmpTabBase = genEmitJumpTable(treeNode, true);

    GetEmitter()->emitIns_R_C(INS_addi, EA_PTRSIZE, treeNode->GetRegNum(), REG_NA,
                              m_compiler->eeFindJitDataOffs(jmpTabBase));
    genProduceReg(treeNode);
}

void CodeGen::genJumpToThrowHlpBlk_la(SpecialCodeKind codeKind,
                                      instruction     ins,
                                      regNumber       reg1,
                                      BasicBlock*     failBlk,
                                      regNumber       reg2)
{
    assert((ins == INS_beq) || (ins == INS_bne) || (ins == INS_blt) || (ins == INS_bge) || (ins == INS_bgt) ||
           (ins == INS_ble));

    if ((reg2 == REG_NA) || (reg2 == REG_R0))
    {
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_R0, 0);
        reg2 = REG_R0;
    }

    GetEmitter()->emitIns_R_R(INS_cmpd, EA_PTRSIZE, reg1, reg2);

    if (m_compiler->fgUseThrowHelperBlocks())
    {
        BasicBlock* excpRaisingBlock;

        if (failBlk != nullptr)
        {
            excpRaisingBlock = failBlk;

#ifdef DEBUG
            Compiler::AddCodeDsc* add = m_compiler->fgGetExcptnTarget(codeKind, m_compiler->compCurBB);
            assert(add->acdUsed);
            assert(excpRaisingBlock == add->acdDstBlk);
#endif
        }
        else
        {
            Compiler::AddCodeDsc* add = m_compiler->fgGetExcptnTarget(codeKind, m_compiler->compCurBB);
            assert((add != nullptr) && "failed to find exception throw block");
            assert(add->acdUsed);
            excpRaisingBlock = add->acdDstBlk;
        }

        GetEmitter()->emitIns_J(ins, excpRaisingBlock);
    }
    else
    {
        BasicBlock* skipLabel = genCreateTempLabel();
        GetEmitter()->emitIns_J(ppcReverseBranchIns(ins), skipLabel);

        genEmitHelperCall(m_compiler->acdHelper(codeKind), 0, EA_UNKNOWN);

        genDefineTempLabel(skipLabel);
    }
}

void CodeGen::genRangeCheck(GenTree* oper)
{
    assert(oper->OperIs(GT_BOUNDS_CHECK));

    GenTreeBoundsChk* bndsChk = oper->AsBoundsChk();
    GenTree*          index   = bndsChk->GetIndex();
    GenTree*          length  = bndsChk->GetArrayLength();

    regNumber indexReg  = genConsumeReg(index);
    regNumber lengthReg = genConsumeReg(length);

    var_types indexType  = genActualType(index);
    var_types lengthType = genActualType(length);

    assert((indexType == TYP_INT) || (indexType == TYP_LONG));
    assert((lengthType == TYP_INT) || (lengthType == TYP_LONG));

    emitAttr cmpSize = ((indexType == TYP_LONG) || (lengthType == TYP_LONG)) ? EA_8BYTE : EA_4BYTE;
    if (cmpSize == EA_8BYTE)
    {
        if (indexType == TYP_INT)
        {
            regNumber tempReg = internalRegisters.Extract(oper);
            GetEmitter()->emitIns_R_R(INS_extsw, EA_PTRSIZE, tempReg, indexReg);
            indexReg = tempReg;
        }

        if (lengthType == TYP_INT)
        {
            regNumber tempReg = internalRegisters.Extract(oper);
            GetEmitter()->emitIns_R_R(INS_extsw, EA_PTRSIZE, tempReg, lengthReg);
            lengthReg = tempReg;
        }
    }

    GetEmitter()->emitIns_R_R((cmpSize == EA_4BYTE) ? INS_cmplw : INS_cmpld, cmpSize, indexReg, lengthReg);

    if (m_compiler->fgUseThrowHelperBlocks())
    {
        Compiler::AddCodeDsc* add = m_compiler->fgGetExcptnTarget(bndsChk->gtThrowKind, m_compiler->compCurBB);
        assert((add != nullptr) && "failed to find range check throw block");
        assert(add->acdUsed);

        GetEmitter()->emitIns_J(INS_bge, add->acdDstBlk);
    }
    else
    {
        BasicBlock* skipLabel = genCreateTempLabel();
        GetEmitter()->emitIns_J(INS_blt, skipLabel);

        genEmitHelperCall(m_compiler->acdHelper(bndsChk->gtThrowKind), 0, EA_UNKNOWN);

        genDefineTempLabel(skipLabel);
    }
}

bool CodeGen::genInstrWithConstant(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, ssize_t imm, regNumber tmpReg, bool inUnwindRegion)
{
    assert(tmpReg != reg2);

#ifdef DEBUG
    switch (ins)
    {
        case INS_addi:
        case INS_ld:
        case INS_lwa:
        case INS_lwz:
        case INS_lhz:
        case INS_lbz:
        case INS_lfs:
        case INS_lfd:
        case INS_std:
        case INS_stw:
        case INS_sth:
        case INS_stb:
        case INS_stfs:
        case INS_stfd:
            break;

        default:
            assert(!"Unexpected instruction in genInstrWithConstant");
            break;
    }
#endif

    if (ppcOffsetFitsInstruction(ins, imm))
    {
        if ((ins == INS_lwa) && ((imm & 0x3) != 0))
        {
            GetEmitter()->emitIns_R_R_I(INS_lwz, attr, reg1, reg2, imm);
            GetEmitter()->emitIns_R_R(INS_extsw, EA_PTRSIZE, reg1, reg1);
            return true;
        }

        GetEmitter()->emitIns_R_R_I(ins, attr, reg1, reg2, imm);
        return true;
    }

    assert(tmpReg != REG_NA);
    assert(!EA_IS_RELOC(EA_SIZE(attr)));

    instGen_Set_Reg_To_Imm(EA_PTRSIZE, tmpReg, imm);
    regSet.verifyRegUsed(tmpReg);

    if (inUnwindRegion)
    {
        m_compiler->unwindPadding();
    }

    if (ins == INS_addi)
    {
        GetEmitter()->emitIns_R_R_R(INS_add, attr, reg1, reg2, tmpReg);
    }
    else
    {
#ifdef DEBUG
        bool isStore = false;
        switch (ins)
        {
            case INS_std:
            case INS_stw:
            case INS_sth:
            case INS_stb:
            case INS_stfs:
            case INS_stfd:
                isStore = true;
                break;
            default:
                break;
        }
        assert(!isStore || (tmpReg != reg1));
#endif
        GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, tmpReg, reg2, tmpReg);
        GetEmitter()->emitIns_R_R_I(ins, attr, reg1, tmpReg, 0);
    }

    return false;
}

void CodeGen::genStackPointerAdjustment(ssize_t spAdjustment, regNumber tmpReg, bool* pTmpRegIsZero, bool reportUnwindData)
{
    if (emitter::isValidSimm16(spAdjustment))
    {
        GetEmitter()->emitIns_R_R_I(INS_addi, EA_PTRSIZE, REG_SPBASE, REG_SPBASE, spAdjustment);
    }
    else
    {
        if (tmpReg == REG_NA)
        {
            NYI_POWERPC64("large stack adjustment without temporary register");
        }

        instGen_Set_Reg_To_Imm(EA_PTRSIZE, tmpReg, spAdjustment);
        GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, REG_SPBASE, REG_SPBASE, tmpReg);

        if (pTmpRegIsZero != nullptr)
        {
            *pTmpRegIsZero = false;
        }
    }

    if (reportUnwindData)
    {
        ssize_t spDeltaAbs = std::abs(spAdjustment);
        assert((spDeltaAbs % STACK_ALIGN) == 0);
        m_compiler->unwindAllocStack(static_cast<unsigned>(spDeltaAbs));
    }
}

void CodeGen::genEstablishFramePointer(int delta, bool reportUnwindData)
{
    assert(m_compiler->compGeneratingProlog);

    if (delta == 0)
    {
        GetEmitter()->emitIns_Mov(EA_PTRSIZE, REG_FPBASE, REG_SPBASE, /* canSkip */ false);
    }
    else
    {
        if (!emitter::isValidSimm16(delta))
        {
            NYI_POWERPC64("large frame pointer delta");
        }

        GetEmitter()->emitIns_R_R_I(INS_addi, EA_PTRSIZE, REG_FPBASE, REG_SPBASE, delta);
    }

    if (reportUnwindData)
    {
        m_compiler->unwindSetFrameReg(REG_FPBASE, delta);
    }
}

void CodeGen::genSaveCalleeSavedRegistersHelp(regMaskTP regsToSaveMask, int lowestCalleeSavedOffset)
{
    if (regsToSaveMask == RBM_NONE)
    {
        return;
    }

    assert((regsToSaveMask & ~RBM_CALLEE_SAVED) == RBM_NONE);

    if ((regsToSaveMask & RBM_FLT_CALLEE_SAVED) != RBM_NONE)
    {
        NYI_POWERPC64("floating-point callee-saved registers");
    }

    emitter*  emit         = GetEmitter();
    regMaskTP regsMask     = regsToSaveMask & RBM_INT_CALLEE_SAVED;
    uint64_t  maskSaveRegs = static_cast<uint64_t>(regsMask.getLow()) >> FIRST_INT_CALLEE_SAVED;
    regNumber reg          = FIRST_INT_CALLEE_SAVED;

    while (maskSaveRegs != 0)
    {
        if ((maskSaveRegs & 1) != 0)
        {
            if (!emitter::isValidSimm16(lowestCalleeSavedOffset) || (lowestCalleeSavedOffset > 2047))
            {
                NYI_POWERPC64("large callee-saved register offset");
            }

            emit->emitIns_R_R_I(INS_std, EA_PTRSIZE, reg, REG_SPBASE, lowestCalleeSavedOffset);
            m_compiler->unwindSaveReg(reg, lowestCalleeSavedOffset);
            lowestCalleeSavedOffset += REGSIZE_BYTES;
        }

        maskSaveRegs >>= 1;
        reg = REG_NEXT(reg);
    }
}

void CodeGen::genRestoreCalleeSavedRegistersHelp(regMaskTP regsToRestoreMask,
                                                 regNumber baseReg,
                                                 int       lowestCalleeSavedOffset,
                                                 bool      reportUnwindData)
{
    if (regsToRestoreMask == RBM_NONE)
    {
        return;
    }

    assert((regsToRestoreMask & ~RBM_CALLEE_SAVED) == RBM_NONE);

    if ((regsToRestoreMask & RBM_FLT_CALLEE_SAVED) != RBM_NONE)
    {
        NYI_POWERPC64("floating-point callee-saved registers");
    }

    int highestCalleeSavedOffset = lowestCalleeSavedOffset + (genCountBits(regsToRestoreMask) * REGSIZE_BYTES);
    assert((highestCalleeSavedOffset % REGSIZE_BYTES) == 0);

    emitter*  emit         = GetEmitter();
    regMaskTP regsMask     = regsToRestoreMask & RBM_INT_CALLEE_SAVED;
    int64_t   maskSaveRegs = static_cast<int64_t>(regsMask.getLow()) << (63 - LAST_INT_CALLEE_SAVED);
    regNumber reg          = LAST_INT_CALLEE_SAVED;

    while (maskSaveRegs != 0)
    {
        if (maskSaveRegs < 0)
        {
            highestCalleeSavedOffset -= REGSIZE_BYTES;

            if (!emitter::isValidSimm16(highestCalleeSavedOffset) || (highestCalleeSavedOffset > 2047))
            {
                NYI_POWERPC64("large callee-saved register offset");
            }

            emit->emitIns_R_R_I(INS_ld, EA_PTRSIZE, reg, baseReg, highestCalleeSavedOffset);

            if (reportUnwindData)
            {
                m_compiler->unwindSaveReg(reg, highestCalleeSavedOffset);
            }
        }

        maskSaveRegs <<= 1;
        reg = REG_PREV(reg);
    }

    assert(highestCalleeSavedOffset == lowestCalleeSavedOffset);
}

instruction CodeGen::genGetInsForOper(GenTree* treeNode)
{
    switch (treeNode->OperGet())
    {
        case GT_ADD:
            if (varTypeIsFloating(treeNode))
            {
                return (treeNode->TypeGet() == TYP_FLOAT) ? INS_fadds : INS_fadd;
            }
            return INS_add;
        case GT_SUB:
            if (varTypeIsFloating(treeNode))
            {
                return (treeNode->TypeGet() == TYP_FLOAT) ? INS_fsubs : INS_fsub;
            }
            return INS_subf;
        case GT_MUL:
            if (varTypeIsFloating(treeNode))
            {
                return (treeNode->TypeGet() == TYP_FLOAT) ? INS_fmuls : INS_fmul;
            }
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_mullw : INS_mulld;
        case GT_DIV:
            if (varTypeIsFloating(treeNode))
            {
                return (treeNode->TypeGet() == TYP_FLOAT) ? INS_fdivs : INS_fdiv;
            }
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_divw : INS_divd;
        case GT_UDIV:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_divwu : INS_divdu;
        case GT_MOD:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_divw : INS_divd;
        case GT_UMOD:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_divwu : INS_divdu;
        case GT_LSH:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_slw : INS_sld;
        case GT_RSH:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_sraw : INS_srad;
        case GT_RSZ:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_srw : INS_srd;
        case GT_AND:
            return INS_and;
        case GT_AND_NOT:
            return INS_andc;
        case GT_OR:
            return INS_or;
        case GT_OR_NOT:
            return INS_orc;
        case GT_XOR:
            return INS_xor;
        case GT_XOR_NOT:
            return INS_eqv;
        case GT_NEG:
            if (varTypeIsFloating(treeNode))
            {
                return INS_fneg;
            }
            return INS_neg;
        case GT_NOT:
            return INS_not;
        default:
            NYI_POWERPC64("genGetInsForOper");
            return INS_invalid;
    }
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
    assert(isFramePointerUsed());

    int delta = ppcGetLocalFrameSize(m_compiler);
    if ((m_compiler->lvaMonAcquired != BAD_VAR_NUM) && !m_compiler->opts.IsOSR())
    {
        delta -= TARGET_POINTER_SIZE;
    }

    assert(delta >= 0);
    return delta;
}

int CodeGenInterface::genTotalFrameSize() const
{
    assert(!IsUninitialized(m_compiler->compCalleeRegsPushed));

    int fixedFrameSize = PPC_LINK_REGISTER_SAVE_SIZE;
    if (isFramePointerUsed())
    {
        fixedFrameSize += PPC_FRAME_POINTER_SAVE_SIZE;
    }

    unsigned totalFrameSize =
        fixedFrameSize + (m_compiler->compCalleeRegsPushed * REGSIZE_BYTES) + ppcGetLocalFrameSize(m_compiler);
    totalFrameSize          = roundUp(totalFrameSize, STACK_ALIGN);

    assert(totalFrameSize <= INT_MAX);
    return static_cast<int>(totalFrameSize);
}

int CodeGenInterface::genCallerSPtoFPdelta() const
{
    assert(isFramePointerUsed());
    int callerSPtoFPdelta = genCallerSPtoInitialSPdelta() + genSPtoFPdelta();
    assert(callerSPtoFPdelta <= 0);
    return callerSPtoFPdelta;
}

int CodeGenInterface::genCallerSPtoInitialSPdelta() const
{
    int callerSPtoSPdelta = -genTotalFrameSize();
    assert(callerSPtoSPdelta <= 0);
    return callerSPtoSPdelta;
}

void CodeGen::genCreateAndStoreGCInfo(unsigned codeSize, unsigned prologSize, unsigned epilogSize DEBUGARG(void* codePtr))
{
    IAllocator*    allowZeroAlloc = new (m_compiler, CMK_GC) CompIAllocator(m_compiler->getAllocatorGC());
    GcInfoEncoder* gcInfoEncoder  = new (m_compiler, CMK_GC)
        GcInfoEncoder(m_compiler->info.compCompHnd, m_compiler->info.compMethodInfo, allowZeroAlloc, NOMEM);
    assert(gcInfoEncoder != nullptr);

    gcInfo.gcInfoBlockHdrSave(gcInfoEncoder, codeSize, prologSize);

    unsigned callCnt = 0;
    gcInfo.gcMakeRegPtrTable(gcInfoEncoder, codeSize, prologSize, GCInfo::MAKE_REG_PTR_MODE_ASSIGN_SLOTS, &callCnt);
    gcInfoEncoder->FinalizeSlotIds();
    gcInfo.gcMakeRegPtrTable(gcInfoEncoder, codeSize, prologSize, GCInfo::MAKE_REG_PTR_MODE_DO_WORK, &callCnt);

    if (m_compiler->opts.IsReversePInvoke())
    {
        unsigned reversePInvokeFrameVarNumber = m_compiler->lvaReversePInvokeFrameVar;
        assert(reversePInvokeFrameVarNumber != BAD_VAR_NUM);
        const LclVarDsc* reversePInvokeFrameVar = m_compiler->lvaGetDesc(reversePInvokeFrameVarNumber);
        gcInfoEncoder->SetReversePInvokeFrameSlot(reversePInvokeFrameVar->GetStackOffset());
    }

    gcInfoEncoder->Build();

    m_compiler->compInfoBlkAddr = gcInfoEncoder->Emit();
    m_compiler->compInfoBlkSize = gcInfoEncoder->GetEncodedGCInfoSize();
}

void CodeGen::genEmitHelperCall(unsigned helper, int argSize, emitAttr retSize, regNumber callTargetReg)
{
    EmitCallParams params;

    CORINFO_CONST_LOOKUP helperFunction = m_compiler->compGetHelperFtn(static_cast<CorInfoHelpFunc>(helper));
    regMaskTP            killSet        = m_compiler->compHelperCallKillSet(static_cast<CorInfoHelpFunc>(helper));
    bool                 restoreTocAfterHelperCall = false;
    const bool           helperUsesExternalToc =
        TargetOS::IsUnix && !m_compiler->IsTargetAbi(CORINFO_NATIVEAOT_ABI);

    if (callTargetReg == REG_NA)
    {
        callTargetReg = REG_DEFAULT_HELPER_CALL_TARGET;
    }

    if (helperUsesExternalToc)
    {
        callTargetReg = REG_INDIRECT_CALL_TARGET_REG;
        GetEmitter()->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_R2, REG_SPBASE, PPC_TOC_SAVE_OFFSET);
        restoreTocAfterHelperCall = true;
    }

    regMaskTP callTargetMask = genRegMask(callTargetReg);
    noway_assert((callTargetMask & killSet) == callTargetMask);

    if ((helperFunction.accessType == IAT_VALUE) && m_compiler->opts.compReloc)
    {
        params.callType = helperUsesExternalToc ? EC_FUNC_TOKEN_GOT : EC_FUNC_TOKEN;
        params.addr     = helperFunction.addr;
    }
    else if (helperFunction.accessType == IAT_VALUE)
    {
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, callTargetReg, reinterpret_cast<ssize_t>(helperFunction.addr));
        params.callType = EC_INDIR_R;
        params.ireg     = callTargetReg;
    }
    else
    {
        assert(helperFunction.accessType == IAT_PVALUE);

        instGen_Set_Reg_To_Imm(EA_PTRSIZE, callTargetReg, reinterpret_cast<ssize_t>(helperFunction.addr));
        GetEmitter()->emitIns_R_R_I(INS_ld, EA_PTRSIZE, callTargetReg, callTargetReg, 0);
        params.callType = EC_INDIR_R;
        params.ireg     = callTargetReg;
    }

    if (params.callType == EC_INDIR_R)
    {
        regSet.verifyRegUsed(callTargetReg);
    }

    params.methHnd  = m_compiler->eeFindHelper(helper);
    params.argSize  = argSize;
    params.retSize  = retSize;

    genEmitCallWithCurrentGC(params);

    if (restoreTocAfterHelperCall)
    {
        GetEmitter()->emitIns_R_R_I(INS_ld, EA_PTRSIZE, REG_R2, REG_SPBASE, PPC_TOC_SAVE_OFFSET);
    }

    regSet.verifyRegistersUsed(killSet);
}

void CodeGen::genLclHeap(GenTree* tree)
{
    assert(tree->OperIs(GT_LCLHEAP));
    assert(m_compiler->compLocallocUsed);
    assert(isFramePointerUsed());
    assert(genStackLevel == 0);

    emitter* emit = GetEmitter();
    GenTree* size = tree->AsOp()->gtOp1;
    assert((genActualType(size->TypeGet()) == TYP_INT) || (genActualType(size->TypeGet()) == TYP_I_IMPL));

    regNumber            targetReg                = tree->GetRegNum();
    regNumber            regCnt                   = REG_NA;
    regNumber            tempReg                  = REG_NA;
    regNumber            spSourceReg              = REG_SPBASE;
    var_types            type                     = genActualType(size->TypeGet());
    const target_size_t  pageSize                 = m_compiler->eeGetPageSize();
    BasicBlock*          endLabel                 = nullptr;
    unsigned             stackAdjustment          = 0;
    const target_ssize_t ILLEGAL_LAST_TOUCH_DELTA = (target_ssize_t)-1;
    target_ssize_t       lastTouchDelta           = ILLEGAL_LAST_TOUCH_DELTA;

    size_t amount = 0;
    if (size->IsCnsIntOrI())
    {
        assert(size->isContained());

        amount = size->AsIntCon()->gtIconVal;
        if (amount == 0)
        {
            instGen_Set_Reg_To_Zero(EA_PTRSIZE, targetReg);
            goto BAILOUT;
        }

        amount = AlignUp(amount, STACK_ALIGN);
    }
    else
    {
        genConsumeRegAndCopy(size, targetReg);

        endLabel = genCreateTempLabel();
        instGen_Set_Reg_To_Zero(EA_PTRSIZE, REG_R0);
        ppcEmitCompareAndBranch(emit, INS_cmpd, targetReg, REG_R0, INS_beq, endLabel);

        if (m_compiler->info.compInitMem)
        {
            regCnt = targetReg;
        }
        else
        {
            regCnt = internalRegisters.Extract(tree);
            if (regCnt != targetReg)
            {
                emit->emitIns_Mov(emitActualTypeSize(type), regCnt, targetReg, /* canSkip */ true);
            }
        }

        genInstrWithConstant(INS_addi, emitActualTypeSize(type), regCnt, regCnt, STACK_ALIGN - 1, REG_R0);
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_R0, -static_cast<ssize_t>(STACK_ALIGN));
        emit->emitIns_R_R_R(INS_and, emitActualTypeSize(type), regCnt, regCnt, REG_R0);
    }

    if (m_compiler->lvaOutgoingArgSpaceSize > 0)
    {
        unsigned outgoingArgSpaceAligned = roundUp(m_compiler->lvaOutgoingArgSpaceSize, STACK_ALIGN);
        tempReg                          = internalRegisters.Extract(tree);
        genInstrWithConstant(INS_addi, EA_PTRSIZE, REG_SPBASE, REG_SPBASE, outgoingArgSpaceAligned, tempReg);
        stackAdjustment += outgoingArgSpaceAligned;
    }

    if (size->IsCnsIntOrI())
    {
        assert(amount > 0);

        size_t slotPairCount = amount / (REGSIZE_BYTES * 2);
        if (m_compiler->info.compInitMem && (slotPairCount <= 4))
        {
            genStackPointerAdjustment(-static_cast<ssize_t>(amount), tempReg, nullptr, /* reportUnwindData */ false);
            instGen_Set_Reg_To_Zero(EA_PTRSIZE, REG_R0);

            ssize_t offset = static_cast<ssize_t>(amount);
            while (slotPairCount != 0)
            {
                offset -= REGSIZE_BYTES;
                emit->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_R0, REG_SPBASE, offset);
                offset -= REGSIZE_BYTES;
                emit->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_R0, REG_SPBASE, offset);
                slotPairCount--;
            }

            lastTouchDelta = 0;
            goto ALLOC_DONE;
        }

        if (!m_compiler->info.compInitMem && (amount < pageSize))
        {
            emit->emitIns_R_R_I(INS_lwz, EA_4BYTE, REG_R0, REG_SPBASE, 0);
            lastTouchDelta = amount;
            genStackPointerAdjustment(-static_cast<ssize_t>(amount), tempReg, nullptr, /* reportUnwindData */ false);
            goto ALLOC_DONE;
        }

        assert(regCnt == REG_NA);
        regCnt = m_compiler->info.compInitMem ? targetReg : internalRegisters.Extract(tree);
        instGen_Set_Reg_To_Imm((amount <= UINT32_MAX) ? EA_4BYTE : EA_8BYTE, regCnt, static_cast<ssize_t>(amount));
    }

    if (m_compiler->info.compInitMem)
    {
        BasicBlock* loop = genCreateTempLabel();
        genDefineTempLabel(loop);

        emit->emitIns_R_R_I(INS_addi, EA_PTRSIZE, REG_SPBASE, REG_SPBASE, -static_cast<ssize_t>(REGSIZE_BYTES * 2));
        instGen_Set_Reg_To_Zero(EA_PTRSIZE, REG_R0);
        emit->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_R0, REG_SPBASE, REGSIZE_BYTES);
        emit->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_R0, REG_SPBASE, 0);

        assert(genIsValidIntReg(regCnt));
        emit->emitIns_R_R_I(INS_addi, emitActualTypeSize(type), regCnt, regCnt,
                            -static_cast<ssize_t>(REGSIZE_BYTES * 2));
        ppcEmitCompareAndBranch(emit, INS_cmpd, regCnt, REG_R0, INS_bne, loop);

        lastTouchDelta = 0;
    }
    else
    {
        if (tempReg == REG_NA)
        {
            tempReg = internalRegisters.Extract(tree);
        }

        assert(regCnt != tempReg);

        // regCnt now holds the final SP value.
        emit->emitIns_R_R_R(INS_subf, EA_PTRSIZE, regCnt, regCnt, REG_SPBASE);

        regNumber pageReg = internalRegisters.GetSingle(tree);
        noway_assert(pageReg != tempReg);
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, pageReg, static_cast<ssize_t>(pageSize));
        regSet.verifyRegUsed(pageReg);

        emit->emitIns_Mov(EA_PTRSIZE, tempReg, REG_SPBASE, /* canSkip */ false);

        BasicBlock* loop = genCreateTempLabel();
        genDefineTempLabel(loop);
        emit->emitIns_R_R_I(INS_lwz, EA_4BYTE, REG_R0, tempReg, 0);
        emit->emitIns_R_R_R(INS_subf, EA_PTRSIZE, tempReg, pageReg, tempReg);
        ppcEmitCompareAndBranch(emit, INS_cmpld, tempReg, regCnt, INS_bge, loop);

        emit->emitIns_Mov(EA_PTRSIZE, REG_SPBASE, regCnt, /* canSkip */ false);
        spSourceReg = regCnt;
    }

ALLOC_DONE:
    if (stackAdjustment != 0)
    {
        assert((stackAdjustment % STACK_ALIGN) == 0);
        assert((lastTouchDelta == ILLEGAL_LAST_TOUCH_DELTA) || (lastTouchDelta >= 0));

        if ((lastTouchDelta == ILLEGAL_LAST_TOUCH_DELTA) ||
            (stackAdjustment + static_cast<unsigned>(lastTouchDelta) + STACK_PROBE_BOUNDARY_THRESHOLD_BYTES > pageSize))
        {
            emit->emitIns_R_R_I(INS_lwz, EA_4BYTE, REG_R0, REG_SPBASE, 0);
        }

        genStackPointerAdjustment(-static_cast<ssize_t>(stackAdjustment), tempReg, nullptr,
                                  /* reportUnwindData */ false);
        genInstrWithConstant(INS_addi, EA_PTRSIZE, targetReg, REG_SPBASE, static_cast<ssize_t>(stackAdjustment),
                             tempReg);
    }
    else
    {
        emit->emitIns_Mov(EA_PTRSIZE, targetReg, spSourceReg, /* canSkip */ true);
    }

BAILOUT:
    if (endLabel != nullptr)
    {
        genDefineTempLabel(endLabel);
    }

    genProduceReg(tree);
}

void CodeGen::genPutArgStk(GenTreePutArgStk* treeNode)
{
    assert(treeNode->OperIs(GT_PUTARG_STK));

    if (treeNode->putInIncomingArgArea())
    {
        NYI_POWERPC64("fast tail call stack arguments");
    }

    unsigned varNumOut    = m_compiler->lvaOutgoingArgSpaceVar;
    unsigned argOffsetOut = treeNode->getArgOffset();
    unsigned argOffsetMax = m_compiler->lvaOutgoingArgSpaceSize;
    GenTree* source       = treeNode->gtGetOp1();

    if (!source->TypeIs(TYP_STRUCT))
    {
        var_types   slotType  = genActualType(source);
        instruction storeIns  = ins_Store(slotType);
        emitAttr    storeAttr = emitTypeSize(slotType);

        if ((EA_SIZE(storeAttr) < EA_PTRSIZE) && varTypeUsesIntReg(slotType))
        {
            storeAttr = EA_PTRSIZE;
            storeIns  = INS_std;
        }

        if (source->isContained())
        {
            assert(source->OperIs(GT_CNS_INT));
            assert(source->AsIntConCommon()->IconValue() == 0);

            instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_R0, 0);

            regNumber baseReg = REG_NA;
            int       offset  = ppcGetLclFrameOffset(m_compiler, varNumOut, argOffsetOut, &baseReg);
            if (treeNode->isSplitStackArg())
            {
                offset -= FIRST_ARG_STACK_OFFS;
            }
            regNumber tmpReg  = ppcOffsetFitsInstruction(storeIns, offset) ? REG_NA : internalRegisters.GetSingle(treeNode);
            genInstrWithConstant(storeIns, storeAttr, REG_R0, baseReg, offset, tmpReg);
        }
        else
        {
            genConsumeReg(source);

            regNumber baseReg = REG_NA;
            int       offset  = ppcGetLclFrameOffset(m_compiler, varNumOut, argOffsetOut, &baseReg);
            if (treeNode->isSplitStackArg())
            {
                offset -= FIRST_ARG_STACK_OFFS;
            }
            regNumber tmpReg  = ppcOffsetFitsInstruction(storeIns, offset) ? REG_NA : internalRegisters.GetSingle(treeNode);
            genInstrWithConstant(storeIns, storeAttr, source->GetRegNum(), baseReg, offset, tmpReg);
        }

        argOffsetOut += EA_SIZE_IN_BYTES(storeAttr);
        assert(argOffsetOut <= argOffsetMax);
        return;
    }

    assert(source->isContained());

    if (source->OperIs(GT_FIELD_LIST))
    {
        const unsigned argOffset = treeNode->getArgOffset();
        // Split arguments use ABI stack offsets directly for their stack segments.
        // Full stack arguments live past the caller linkage and parameter-save area.
        const bool addPpc64leStackArgBias = !treeNode->isSplitStackArg();
        regNumber  tmpReg                 = REG_NA;

        for (GenTreeFieldList::Use& use : source->AsFieldList()->Uses())
        {
            GenTree* nextArgNode = use.GetNode();
            genConsumeReg(nextArgNode);

            regNumber reg    = nextArgNode->GetRegNum();
            var_types type   = use.GetType();
            emitAttr  attr   = emitTypeSize(type);
            unsigned  offset = argOffset + use.GetOffset();

            instruction storeIns = ins_Store(type);
            bool        fpBased  = false;
            int         frameOff = m_compiler->lvaFrameAddress(varNumOut, &fpBased) + static_cast<int>(offset);
            if (addPpc64leStackArgBias)
            {
                frameOff += FIRST_ARG_STACK_OFFS;
            }

            if (!ppcOffsetFitsInstruction(storeIns, frameOff))
            {
                if (tmpReg == REG_NA)
                {
                    tmpReg = internalRegisters.GetSingle(treeNode);
                }
            }

            regNumber baseReg = fpBased ? REG_FPBASE : REG_SPBASE;
            genInstrWithConstant(storeIns, attr, reg, baseReg, frameOff, tmpReg);
        }
        return;
    }

    noway_assert(source->OperIsLocalRead() || source->OperIs(GT_BLK));

    regNumber loReg = internalRegisters.Extract(treeNode);

    GenTreeLclVarCommon* srcLclNode = nullptr;
    regNumber            addrReg    = REG_NA;
    ClassLayout*         layout     = nullptr;

    if (source->OperIsLocalRead())
    {
        srcLclNode        = source->AsLclVarCommon();
        layout            = srcLclNode->GetLayout(m_compiler);
        LclVarDsc* varDsc = m_compiler->lvaGetDesc(srcLclNode);

        assert(varDsc->lvOnFrame && !varDsc->lvRegister);
    }
    else
    {
        layout  = source->AsBlk()->GetLayout();
        addrReg = genConsumeReg(source->AsBlk()->Addr());
    }

    unsigned srcSize = layout->GetSize();
    noway_assert(srcSize <= MAX_PASS_MULTIREG_BYTES);

    unsigned dstSize = treeNode->GetStackByteSize();

    if ((dstSize != srcSize) && (srcLclNode != nullptr))
    {
        unsigned widenedSrcSize = roundUp(srcSize, TARGET_POINTER_SIZE);
        if (widenedSrcSize <= dstSize)
        {
            srcSize = widenedSrcSize;
        }
    }

    assert(srcSize <= dstSize);

    int      remainingSize = srcSize;
    unsigned structOffset  = 0;
    unsigned lclOffset     = (srcLclNode != nullptr) ? srcLclNode->GetLclOffs() : 0;

    regNumber dstTmpReg = REG_NA;
    {
        regNumber baseReg             = REG_NA;
        int       initialDstOffset    = ppcGetLclFrameOffset(m_compiler, varNumOut, argOffsetOut, &baseReg);
        bool      dstOffsetRangeFits  = ppcOffsetRangeFitsSimm16(initialDstOffset, srcSize) &&
                                        ppcOffsetFitsInstruction(INS_std, initialDstOffset);
        dstTmpReg = dstOffsetRangeFits ? REG_NA : internalRegisters.Extract(treeNode);
    }

    while (remainingSize > 0)
    {
        unsigned  nextIndex = structOffset / TARGET_POINTER_SIZE;
        var_types type;

        if (remainingSize >= TARGET_POINTER_SIZE)
        {
            type = layout->GetGCPtrType(nextIndex);
        }
        else
        {
            assert(!layout->IsGCPtr(nextIndex));

            if (remainingSize >= 4)
            {
                type = TYP_INT;
            }
            else if (remainingSize >= 2)
            {
                type = TYP_USHORT;
            }
            else
            {
                assert(remainingSize == 1);
                type = TYP_UBYTE;
            }
        }

        emitAttr attr     = emitActualTypeSize(type);
        unsigned moveSize = genTypeSize(type);
        remainingSize -= moveSize;

        instruction loadIns = ins_Load(type);
        if (srcLclNode != nullptr)
        {
            regNumber baseReg = REG_NA;
            int       offset  = ppcGetLclFrameOffset(m_compiler, srcLclNode->GetLclNum(), lclOffset + structOffset,
                                                     &baseReg);
            genInstrWithConstant(loadIns, attr, loReg, baseReg, offset, loReg);
        }
        else
        {
            assert(loReg != addrReg);
            genInstrWithConstant(loadIns, attr, loReg, addrReg, structOffset, loReg);
        }

        regNumber baseReg = REG_NA;
        int       offset  = ppcGetLclFrameOffset(m_compiler, varNumOut, argOffsetOut, &baseReg);
        genInstrWithConstant(ins_Store(type), attr, loReg, baseReg, offset, dstTmpReg);

        argOffsetOut += moveSize;
        assert(argOffsetOut <= argOffsetMax);

        structOffset += moveSize;
    }
}

void CodeGen::genPutArgReg(GenTreeOp* tree)
{
    assert(tree->OperIs(GT_PUTARG_REG));

    var_types targetType = tree->TypeGet();
    regNumber targetReg  = tree->GetRegNum();

    assert(targetType != TYP_STRUCT);

    GenTree* op1 = tree->gtOp1;
    genConsumeReg(op1);

    if (varTypeIsFloating(tree) && emitter::isGeneralRegister(targetReg))
    {
        targetType = (emitActualTypeSize(targetType) == EA_4BYTE) ? TYP_INT : TYP_LONG;
    }

    GetEmitter()->emitIns_Mov(ins_Copy(op1->GetRegNum(), targetType), emitActualTypeSize(targetType), targetReg,
                              op1->GetRegNum(), /* canSkip */ true);
    genProduceReg(tree);
}

void CodeGen::genCall(GenTreeCall* call)
{
    genCallPlaceRegArgs(call);

    if (call->NeedsNullCheck())
    {
        const regNumber regThis = genGetThisArgReg(call);
        GetEmitter()->emitIns_R_R_I(INS_lwz, EA_4BYTE, REG_R0, regThis, 0);
    }

    if (call->IsFastTailCall())
    {
        NYI_POWERPC64("fast tail calls");
    }

    if (m_compiler->killGCRefs(call))
    {
        genDefineTempLabel(genCreateTempLabel());
    }

    genCallInstruction(call);
    genDefinePendingCallLabel(call);

#ifdef DEBUG
    regMaskTP killMask = call->IsHelperCall() ? m_compiler->compHelperCallKillSet(call->GetHelperNum())
                                              : RBM_CALLEE_TRASH;

    assert((gcInfo.gcRegGCrefSetCur & killMask) == 0);
    assert((gcInfo.gcRegByrefSetCur & killMask) == 0);
#endif

    var_types returnType = call->TypeGet();
    if (returnType != TYP_VOID)
    {
        if (call->HasMultiRegRetVal())
        {
            const ReturnTypeDesc* retTypeDesc = call->GetReturnTypeDesc();
            assert(retTypeDesc != nullptr);

            unsigned regCount = retTypeDesc->GetReturnRegCount();
            for (unsigned i = 0; i < regCount; i++)
            {
                var_types regType      = retTypeDesc->GetReturnRegType(i);
                regNumber abiReg       = retTypeDesc->GetABIReturnReg(i, call->GetUnmanagedCallConv());
                regNumber allocatedReg = call->GetRegNumByIdx(i);
                inst_Mov(regType, allocatedReg, abiReg, /* canSkip */ true);
            }
        }
        else
        {
            regNumber returnReg = varTypeUsesFloatArgReg(returnType) ? REG_FLOATRET : REG_INTRET;
            if (call->GetRegNum() != returnReg)
            {
                inst_Mov(returnType, call->GetRegNum(), returnReg, /* canSkip */ false);
            }
        }

        genProduceReg(call);
    }

    if ((call->gtNext == nullptr) && !m_compiler->opts.MinOpts() && !m_compiler->opts.compDbgCode)
    {
        gcInfo.gcMarkRegSetNpt(RBM_INTRET);
    }
}

void CodeGen::genCallInstruction(GenTreeCall* call)
{
    const ReturnTypeDesc* retTypeDesc = call->GetReturnTypeDesc();
    EmitCallParams        params;

    if (!call->IsUnusedValue())
    {
        if (call->HasMultiRegRetVal())
        {
            params.retSize       = emitTypeSize(retTypeDesc->GetReturnRegType(0));
            params.secondRetSize = emitTypeSize(retTypeDesc->GetReturnRegType(1));
        }
        else if (call->TypeIs(TYP_REF))
        {
            params.retSize = EA_GCREF;
        }
        else if (call->TypeIs(TYP_BYREF))
        {
            params.retSize = EA_BYREF;
        }
    }

    params.hasAsyncRet = call->IsAsync();

    if (m_compiler->opts.compDbgInfo && (m_compiler->genCallSite2DebugInfoMap != nullptr) && !call->IsTailCall())
    {
        DebugInfo di;
        (void)m_compiler->genCallSite2DebugInfoMap->Lookup(call, &di);
        params.debugInfo = di;
    }

#ifdef DEBUG
    if (!call->IsHelperCall())
    {
        params.sigInfo = call->callSig;
    }
#endif

    regNumber callThroughIndirReg = REG_NA;
    if (!call->IsHelperCall(CORINFO_HELP_DISPATCH_INDIRECT_CALL))
    {
        callThroughIndirReg = getCallIndirectionCellReg(call);
    }

    GenTree* target = getCallTarget(call, &params.methHnd);
    if (target != nullptr)
    {
        if (!target->isContainedIntOrIImmed())
        {
            genConsumeReg(target);
            params.ireg = target->GetRegNum();
        }
        else if (m_compiler->opts.compReloc && target->AsIntCon()->ImmedValNeedsReloc(m_compiler))
        {
            params.callType = EC_FUNC_TOKEN;
            params.addr     = reinterpret_cast<void*>(target->AsIntCon()->IconValue());
        }
        else
        {
            params.ireg = internalRegisters.GetSingle(call);
            instGen_Set_Reg_To_Imm(EA_PTRSIZE, params.ireg, target->AsIntCon()->IconValue());
        }
    }
    else
    {
        if (callThroughIndirReg != REG_NA)
        {
            params.ireg = internalRegisters.GetSingle(call);
            GetEmitter()->emitIns_R_R_I(ins_Load(TYP_I_IMPL), emitActualTypeSize(TYP_I_IMPL), params.ireg,
                                        callThroughIndirReg, 0);
        }
        else
        {
            assert(call->IsHelperCall() || (call->gtCallType == CT_USER_FUNC));
            assert(call->gtDirectCallAddress != nullptr);

            if (m_compiler->opts.compReloc)
            {
                params.callType = EC_FUNC_TOKEN;
                params.addr     = call->gtDirectCallAddress;
            }
            else
            {
                params.ireg = REG_DEFAULT_HELPER_CALL_TARGET;
                instGen_Set_Reg_To_Imm(EA_PTRSIZE, params.ireg, reinterpret_cast<ssize_t>(call->gtDirectCallAddress));
            }
        }
    }

    bool restoreTocAfterExternalCall = false;
    const bool isRuntimeHelper =
        call->IsHelperCall() ||
        ((params.methHnd != NO_METHOD_HANDLE) && (Compiler::eeGetHelperNum(params.methHnd) != CORINFO_HELP_UNDEF));
    const bool helperUsesExternalToc =
        TargetOS::IsUnix && !m_compiler->IsTargetAbi(CORINFO_NATIVEAOT_ABI) && isRuntimeHelper;
    if (call->IsUnmanaged() && (params.callType == EC_FUNC_TOKEN))
    {
        // ELFv2 global entry points derive the callee TOC from r12. Direct unmanaged
        // calls load the external function address through the GOT and branch through
        // r12, avoiding linker-inserted PLT entries in managed code.
        GetEmitter()->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_R2, REG_SPBASE, PPC_TOC_SAVE_OFFSET);
        params.callType = EC_FUNC_TOKEN_GOT;
        restoreTocAfterExternalCall = true;
    }
    else if (helperUsesExternalToc && (params.callType == EC_FUNC_TOKEN))
    {
        GetEmitter()->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_R2, REG_SPBASE, PPC_TOC_SAVE_OFFSET);
        params.callType = EC_FUNC_TOKEN_GOT;
        restoreTocAfterExternalCall = true;
    }
    else if (params.callType != EC_FUNC_TOKEN)
    {
        assert(genIsValidIntReg(params.ireg));

        // ELFv2 global entry points derive the callee TOC from r12. Keep
        // indirect calls ABI-shaped by branching through r12. R2R and VSD calls
        // keep their indirection cell in REG_R2R_INDIRECT_PARAM/r11.
        if (params.ireg != REG_INDIRECT_CALL_TARGET_REG)
        {
            inst_Mov(TYP_I_IMPL, REG_INDIRECT_CALL_TARGET_REG, params.ireg, /* canSkip */ false);
            params.ireg = REG_INDIRECT_CALL_TARGET_REG;
        }

        if (call->IsUnmanaged() || helperUsesExternalToc)
        {
            // ELFv2 global entry points derive the callee TOC from r12, so external indirect
            // calls must branch through r12 and restore the managed TOC after the call returns.
            GetEmitter()->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_R2, REG_SPBASE, PPC_TOC_SAVE_OFFSET);

            restoreTocAfterExternalCall = true;
        }

        regSet.verifyRegUsed(params.ireg);

        params.callType = EC_INDIR_R;
    }

    genEmitCallWithCurrentGC(params);

    if (restoreTocAfterExternalCall)
    {
        GetEmitter()->emitIns_R_R_I(INS_ld, EA_PTRSIZE, REG_R2, REG_SPBASE, PPC_TOC_SAVE_OFFSET);
    }
}

void CodeGen::genPushCalleeSavedRegisters(regNumber initReg, bool* pInitRegZeroed)
{
    assert(m_compiler->compGeneratingProlog);

    regMaskTP rsPushRegs = regSet.rsGetModifiedCalleeSavedRegsMask();

    if ((rsPushRegs & RBM_FLT_CALLEE_SAVED) != RBM_NONE)
    {
        NYI_POWERPC64("floating-point callee-saved registers");
    }

    regSet.rsMaskCalleeSaved = rsPushRegs;

#ifdef DEBUG
    if (m_compiler->compCalleeRegsPushed != genCountBits(rsPushRegs))
    {
        printf("Error: unexpected number of callee-saved registers to save. Expected: %d. Got: %d ",
               m_compiler->compCalleeRegsPushed, genCountBits(rsPushRegs));
        dspRegMask(rsPushRegs);
        printf("\n");
        assert(m_compiler->compCalleeRegsPushed == genCountBits(rsPushRegs));
    }
#endif
}

void CodeGen::genPopCalleeSavedRegisters(bool jmpEpilog)
{
    assert(m_compiler->compGeneratingEpilog);

    regMaskTP regsToRestoreMask = regSet.rsGetModifiedCalleeSavedRegsMask();

    if ((regsToRestoreMask & RBM_FLT_CALLEE_SAVED) != RBM_NONE)
    {
        NYI_POWERPC64("floating-point callee-saved registers");
    }

    int framePointerOffset = ppcGetLocalFrameSize(m_compiler);
    int linkRegisterOffset = framePointerOffset;
    int calleeSaveOffset   = linkRegisterOffset + PPC_LINK_REGISTER_SAVE_SIZE;
    int saveAreaSize       = PPC_LINK_REGISTER_SAVE_SIZE + (m_compiler->compCalleeRegsPushed * REGSIZE_BYTES);

    if (isFramePointerUsed())
    {
        if (m_compiler->compLocallocUsed)
        {
            int spToFPDelta = genSPtoFPdelta();
            if (emitter::isValidSimm16(-spToFPDelta))
            {
                GetEmitter()->emitIns_R_R_I(INS_addi, EA_PTRSIZE, REG_SPBASE, REG_FPBASE, -spToFPDelta);
            }
            else
            {
                instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_TMP_0, spToFPDelta);
                GetEmitter()->emitIns_R_R_R(INS_subf, EA_PTRSIZE, REG_SPBASE, REG_TMP_0, REG_FPBASE);
            }
        }

        linkRegisterOffset = framePointerOffset + PPC_FRAME_POINTER_SAVE_SIZE;
        calleeSaveOffset   = linkRegisterOffset + PPC_LINK_REGISTER_SAVE_SIZE;
        saveAreaSize += PPC_FRAME_POINTER_SAVE_SIZE;
    }

    unsigned maxDeferredFrameSize = static_cast<unsigned>(framePointerOffset);
    if (isFramePointerUsed())
    {
        maxDeferredFrameSize = min(maxDeferredFrameSize, static_cast<unsigned>(genSPtoFPdelta()));
    }

    unsigned deferredFrameSize = ppcGetDeferredFrameSizeForSaveArea(static_cast<unsigned>(framePointerOffset),
                                                                    static_cast<unsigned>(saveAreaSize),
                                                                    maxDeferredFrameSize);
    if (deferredFrameSize != 0)
    {
        framePointerOffset -= static_cast<int>(deferredFrameSize);
        linkRegisterOffset -= static_cast<int>(deferredFrameSize);
        calleeSaveOffset -= static_cast<int>(deferredFrameSize);

        if ((calleeSaveOffset + (genCountBits(regsToRestoreMask) * REGSIZE_BYTES) - REGSIZE_BYTES) >
            PPC_MAX_UNWIND_SAVE_OFFSET)
        {
            NYI_POWERPC64("large callee-saved register offset");
        }

        genStackPointerAdjustment(deferredFrameSize, REG_TMP_0, nullptr, /* reportUnwindData */ true);
    }

    genRestoreCalleeSavedRegistersHelp(regsToRestoreMask, REG_SPBASE, calleeSaveOffset, /* reportUnwindData */ true);

    if (!emitter::isValidSimm16(linkRegisterOffset))
    {
        NYI_POWERPC64("large link register save offset");
    }

    GetEmitter()->emitIns_R_R_I(INS_ld, EA_PTRSIZE, REG_R0, REG_SPBASE, linkRegisterOffset);
    GetEmitter()->emitIns_R_R(INS_mtlr, EA_PTRSIZE, REG_R0, REG_R0);

    if (isFramePointerUsed())
    {
        if (!emitter::isValidSimm16(framePointerOffset))
        {
            NYI_POWERPC64("large frame pointer save offset");
        }

        GetEmitter()->emitIns_R_R_I(INS_ld, EA_PTRSIZE, REG_FPBASE, REG_SPBASE, framePointerOffset);
        m_compiler->unwindSaveReg(REG_FPBASE, framePointerOffset);
    }

    int totalFrameSize = genTotalFrameSize();
    if (totalFrameSize != 0)
    {
        genStackPointerAdjustment(totalFrameSize - deferredFrameSize, REG_TMP_0, nullptr, /* reportUnwindData */ true);
    }
}

void CodeGen::genOSRHandleTier0CalleeSavedRegistersAndFrame()
{
}

void CodeGen::genEstablishPpc64leTocForReversePInvoke()
{
    if (!m_compiler->opts.IsReversePInvoke() || !m_compiler->opts.compReloc)
    {
        return;
    }

    emitter* emit = GetEmitter();
    // PPC64 ELFv2 global entry points are entered with r12 holding the callee
    // entry address. Use the canonical two-instruction REL16 .TOC. sequence to
    // establish this method's TOC before the normal prolog can emit any
    // TOC-relative references.
    emit->emitIns_R_L(INS_lea, EA_PTRSIZE, emit->emitPrologIG, REG_R2, REG_R12);

    m_compiler->unwindPadding();
}

void CodeGen::genAllocLclFrame(unsigned frameSize, regNumber initReg, bool* pInitRegZeroed, regMaskTP maskArgRegsLiveIn)
{
    frameSize = ppcGetLocalFrameSize(m_compiler, frameSize);

    unsigned calleeSaveSize       = m_compiler->compCalleeRegsPushed * REGSIZE_BYTES;
    unsigned framePointerSaveSize = isFramePointerUsed() ? PPC_FRAME_POINTER_SAVE_SIZE : 0;
    unsigned totalFrameSize       = frameSize + framePointerSaveSize + PPC_LINK_REGISTER_SAVE_SIZE + calleeSaveSize;
    totalFrameSize                = roundUp(totalFrameSize, STACK_ALIGN);

    if (totalFrameSize != 0)
    {
        unsigned saveAreaSize = framePointerSaveSize + PPC_LINK_REGISTER_SAVE_SIZE + calleeSaveSize;

        unsigned maxDeferredFrameSize = frameSize;
        if (isFramePointerUsed())
        {
            maxDeferredFrameSize = min(maxDeferredFrameSize, static_cast<unsigned>(genSPtoFPdelta()));
        }

        unsigned deferredFrameSize = ppcGetDeferredFrameSizeForSaveArea(frameSize, saveAreaSize, maxDeferredFrameSize);
        unsigned initialFrameSize  = totalFrameSize - deferredFrameSize;

        genStackPointerAdjustment(-static_cast<ssize_t>(initialFrameSize), initReg, pInitRegZeroed, true);

        unsigned framePointerOffset = frameSize - deferredFrameSize;
        unsigned linkRegisterOffset = framePointerOffset + framePointerSaveSize;
        unsigned calleeSaveOffset   = linkRegisterOffset + PPC_LINK_REGISTER_SAVE_SIZE;

        if (!emitter::isValidSimm16(calleeSaveOffset) || (calleeSaveOffset > 2047))
        {
            NYI_POWERPC64("large link register save offset");
        }

        if (isFramePointerUsed())
        {
            GetEmitter()->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_FPBASE, REG_SPBASE,
                                        static_cast<int>(framePointerOffset));
            m_compiler->unwindSaveReg(REG_FPBASE, static_cast<int>(framePointerOffset));
        }

        GetEmitter()->emitIns_R_R(INS_mflr, EA_PTRSIZE, REG_R0, REG_R0);
        GetEmitter()->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_R0, REG_SPBASE, static_cast<int>(linkRegisterOffset));
        m_compiler->unwindSaveLinkRegister(static_cast<int>(linkRegisterOffset));

        genSaveCalleeSavedRegistersHelp(regSet.rsMaskCalleeSaved, static_cast<int>(calleeSaveOffset));

        if (isFramePointerUsed())
        {
            genEstablishFramePointer(genSPtoFPdelta() - static_cast<int>(deferredFrameSize),
                                     /* reportUnwindData */ true);
        }

        if (deferredFrameSize != 0)
        {
            genStackPointerAdjustment(-static_cast<ssize_t>(deferredFrameSize), initReg, pInitRegZeroed,
                                      /* reportUnwindData */ !isFramePointerUsed());
        }
    }
}

void CodeGen::genZeroInitFrameUsingBlockInit(int untrLclHi, int untrLclLo, regNumber initReg, bool* pInitRegZeroed)
{
    if (untrLclHi <= untrLclLo)
    {
        return;
    }

    assert((genRegMask(initReg) & calleeRegArgMaskLiveIn) == 0);
    assert((untrLclLo % 4) == 0);

    regNumber rAddr = initReg;
    *pInitRegZeroed = false;

    if (emitter::isValidSimm16(untrLclLo))
    {
        GetEmitter()->emitIns_R_R_I(INS_addi, EA_PTRSIZE, rAddr, genFramePointerReg(), untrLclLo);
    }
    else
    {
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, rAddr, static_cast<ssize_t>(untrLclLo));
        GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, rAddr, genFramePointerReg(), rAddr);
    }

    instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_R0, 0);

    ssize_t bytes = untrLclHi - untrLclLo;
    assert((bytes % 4) == 0);

    if ((untrLclLo & 0x7) != 0)
    {
        assert((untrLclLo & 0x7) == 4);
        GetEmitter()->emitIns_R_R_I(INS_stw, EA_4BYTE, REG_R0, rAddr, 0);
        bytes -= 4;
        if (bytes != 0)
        {
            GetEmitter()->emitIns_R_R_I(INS_addi, EA_PTRSIZE, rAddr, rAddr, 4);
        }
    }

    if (bytes >= (4 * REGSIZE_BYTES))
    {
        regNumber countReg = (rAddr != REG_TMP_0) ? REG_TMP_0 : REG_SCRATCH;
        noway_assert((genRegMask(countReg) & calleeRegArgMaskLiveIn) == 0);

        instGen_Set_Reg_To_Imm(EA_PTRSIZE, countReg, bytes / REGSIZE_BYTES);

        GetEmitter()->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_R0, rAddr, 0);
        GetEmitter()->emitIns_R_R_I(INS_addi, EA_PTRSIZE, rAddr, rAddr, REGSIZE_BYTES);
        GetEmitter()->emitIns_R_R_I(INS_addi, EA_PTRSIZE, countReg, countReg, -1);
        GetEmitter()->emitIns_R_R(INS_cmpd, EA_PTRSIZE, countReg, REG_R0);
        GetEmitter()->emitIns_I(INS_bne, EA_4BYTE, -4 * static_cast<ssize_t>(sizeof(emitter::code_t)));

        bytes %= REGSIZE_BYTES;
    }

    while (bytes >= REGSIZE_BYTES)
    {
        GetEmitter()->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_R0, rAddr, 0);
        bytes -= REGSIZE_BYTES;
        if (bytes != 0)
        {
            GetEmitter()->emitIns_R_R_I(INS_addi, EA_PTRSIZE, rAddr, rAddr, REGSIZE_BYTES);
        }
    }

    if (bytes != 0)
    {
        assert(bytes == 4);
        GetEmitter()->emitIns_R_R_I(INS_stw, EA_4BYTE, REG_R0, rAddr, 0);
        bytes -= 4;
    }

    noway_assert(bytes == 0);
}

void CodeGen::genSetGSSecurityCookie(regNumber initReg, bool* pInitRegZeroed)
{
    assert(m_compiler->compGeneratingProlog);

    if (!m_compiler->getNeedsGSSecurityCookie())
    {
        return;
    }

    if (m_compiler->opts.IsOSR() && m_compiler->info.compPatchpointInfo->HasSecurityCookie())
    {
        return;
    }

    if (m_compiler->gsGlobalSecurityCookieAddr == nullptr)
    {
        noway_assert(m_compiler->gsGlobalSecurityCookieVal != 0);
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, initReg, m_compiler->gsGlobalSecurityCookieVal);
    }
    else
    {
        emitAttr addrAttr = m_compiler->opts.compReloc ? EA_HANDLE_CNS_RELOC : EA_PTRSIZE;
        instGen_Set_Reg_To_Imm(addrAttr, initReg,
                               reinterpret_cast<ssize_t>(m_compiler->gsGlobalSecurityCookieAddr));
        GetEmitter()->emitIns_R_R_I(INS_ld, EA_PTRSIZE, initReg, initReg, 0);
    }

    regNumber baseReg = REG_NA;
    int       offset  = ppcGetLclFrameOffset(m_compiler, m_compiler->lvaGSSecurityCookie, 0, &baseReg);
    regNumber tmpReg =
        ppcOffsetFitsInstruction(INS_std, offset) ? REG_NA : ((initReg != REG_TMP_0) ? REG_TMP_0 : REG_SCRATCH);

    genInstrWithConstant(INS_std, EA_PTRSIZE, initReg, baseReg, offset, tmpReg);

    *pInitRegZeroed = false;
}

void CodeGen::instGen_MemoryBarrier(BarrierKind barrierKind)
{
#ifdef DEBUG
    if (JitConfig.JitNoMemoryBarriers() == 1)
    {
        return;
    }
#endif // DEBUG

    GetEmitter()->emitIns(INS_sync);
}

#ifdef PROFILING_SUPPORTED
void CodeGen::genProfilingEnterCallback(regNumber initReg, bool* pInitRegZeroed)
{
    assert(m_compiler->compGeneratingProlog);

    if (!m_compiler->compIsProfilerHookNeeded())
    {
        return;
    }

    instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_PROFILER_ENTER_ARG_FUNC_ID,
                           reinterpret_cast<ssize_t>(m_compiler->compProfilerMethHnd));

    if (m_compiler->compProfilerMethHndIndirected)
    {
        GetEmitter()->emitIns_R_R_I(INS_ld, EA_PTRSIZE, REG_PROFILER_ENTER_ARG_FUNC_ID,
                                    REG_PROFILER_ENTER_ARG_FUNC_ID, 0);
    }

    ssize_t callerSPOffset = -m_compiler->lvaToCallerSPRelativeOffset(0, isFramePointerUsed());
    genInstrWithConstant(INS_addi, EA_PTRSIZE, REG_PROFILER_ENTER_ARG_CALLER_SP, genFramePointerReg(),
                         callerSPOffset, REG_PROFILER_ENTER_ARG_CALLER_SP);

    genEmitHelperCall(CORINFO_HELP_PROF_FCN_ENTER, 0, EA_UNKNOWN);

    if (((RBM_PROFILER_ENTER_TRASH | RBM_PROFILER_ENTER_ARG_FUNC_ID | RBM_PROFILER_ENTER_ARG_CALLER_SP) &
         genRegMask(initReg)) != RBM_NONE)
    {
        *pInitRegZeroed = false;
    }
}

void CodeGen::genProfilingLeaveCallback(unsigned helper)
{
    assert((helper == CORINFO_HELP_PROF_FCN_LEAVE) || (helper == CORINFO_HELP_PROF_FCN_TAILCALL));

    if (!m_compiler->compIsProfilerHookNeeded())
    {
        return;
    }

    m_compiler->info.compProfilerCallback = true;

    instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_PROFILER_LEAVE_ARG_FUNC_ID,
                           reinterpret_cast<ssize_t>(m_compiler->compProfilerMethHnd));

    if (m_compiler->compProfilerMethHndIndirected)
    {
        GetEmitter()->emitIns_R_R_I(INS_ld, EA_PTRSIZE, REG_PROFILER_LEAVE_ARG_FUNC_ID,
                                    REG_PROFILER_LEAVE_ARG_FUNC_ID, 0);
    }

    gcInfo.gcMarkRegSetNpt(RBM_PROFILER_LEAVE_ARG_FUNC_ID);

    ssize_t callerSPOffset = -m_compiler->lvaToCallerSPRelativeOffset(0, isFramePointerUsed());
    genInstrWithConstant(INS_addi, EA_PTRSIZE, REG_PROFILER_LEAVE_ARG_CALLER_SP, genFramePointerReg(), callerSPOffset,
                         REG_PROFILER_LEAVE_ARG_CALLER_SP);

    gcInfo.gcMarkRegSetNpt(RBM_PROFILER_LEAVE_ARG_CALLER_SP);

    genEmitHelperCall(helper, 0, EA_UNKNOWN);
}
#endif // PROFILING_SUPPORTED

void CodeGen::genFuncletProlog(BasicBlock* block)
{
    assert(block != nullptr);
    assert(m_compiler->bbIsFuncletBeg(block));

    ScopedSetVariable<bool> setGeneratingProlog(&m_compiler->compGeneratingProlog, true);

    gcInfo.gcResetForBB();

    m_compiler->unwindBegProlog();

    int frameSize = genFuncletInfo.fiSpDelta;
    assert(frameSize < 0);

    regMaskTP maskSaveRegs       = genFuncletInfo.fiSaveRegs & RBM_CALLEE_SAVED;
    int       calleeSavedOffset  = genFuncletInfo.fiSP_to_CalleeSaved_delta;
    int       framePointerOffset = calleeSavedOffset - PPC_LINK_REGISTER_SAVE_SIZE - PPC_FRAME_POINTER_SAVE_SIZE;
    int       linkRegisterOffset = framePointerOffset + PPC_FRAME_POINTER_SAVE_SIZE;

    assert(framePointerOffset >= 0);

    unsigned saveAreaSize =
        PPC_FRAME_POINTER_SAVE_SIZE + PPC_LINK_REGISTER_SAVE_SIZE + (genCountBits(maskSaveRegs) * REGSIZE_BYTES);
    unsigned deferredFrameSize = ppcGetDeferredFrameSizeForSaveArea(static_cast<unsigned>(framePointerOffset),
                                                                    saveAreaSize,
                                                                    static_cast<unsigned>(framePointerOffset));
    if (deferredFrameSize != 0)
    {
        frameSize += static_cast<int>(deferredFrameSize);
        framePointerOffset -= static_cast<int>(deferredFrameSize);
        linkRegisterOffset -= static_cast<int>(deferredFrameSize);
        calleeSavedOffset -= static_cast<int>(deferredFrameSize);
    }

    if (!emitter::isValidSimm16(calleeSavedOffset) || (calleeSavedOffset > 2047))
    {
        NYI_POWERPC64("large funclet callee-saved offset");
    }

    genStackPointerAdjustment(frameSize, REG_TMP_0, nullptr, /* reportUnwindData */ true);

    GetEmitter()->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_FPBASE, REG_SPBASE, framePointerOffset);
    m_compiler->unwindSaveReg(REG_FPBASE, framePointerOffset);

    GetEmitter()->emitIns_R_R(INS_mflr, EA_PTRSIZE, REG_R0, REG_R0);
    GetEmitter()->emitIns_R_R_I(INS_std, EA_PTRSIZE, REG_R0, REG_SPBASE, linkRegisterOffset);
    m_compiler->unwindSaveLinkRegister(linkRegisterOffset);

    genSaveCalleeSavedRegistersHelp(maskSaveRegs, calleeSavedOffset);

    if (deferredFrameSize != 0)
    {
        genStackPointerAdjustment(-static_cast<ssize_t>(deferredFrameSize), REG_TMP_0, nullptr,
                                  /* reportUnwindData */ true);
    }

    m_compiler->unwindEndProlog();
}

void CodeGen::genFuncletEpilog(BasicBlock* block)
{
    ScopedSetVariable<bool> setGeneratingEpilog(&m_compiler->compGeneratingEpilog, true);

    m_compiler->unwindBegEpilog();

    int frameSize = genFuncletInfo.fiSpDelta;
    assert(frameSize < 0);

    regMaskTP maskSaveRegs       = genFuncletInfo.fiSaveRegs & RBM_CALLEE_SAVED;
    int       calleeSavedOffset  = genFuncletInfo.fiSP_to_CalleeSaved_delta;
    int       framePointerOffset = calleeSavedOffset - PPC_LINK_REGISTER_SAVE_SIZE - PPC_FRAME_POINTER_SAVE_SIZE;
    int       linkRegisterOffset = framePointerOffset + PPC_FRAME_POINTER_SAVE_SIZE;

    assert(framePointerOffset >= 0);

    unsigned saveAreaSize =
        PPC_FRAME_POINTER_SAVE_SIZE + PPC_LINK_REGISTER_SAVE_SIZE + (genCountBits(maskSaveRegs) * REGSIZE_BYTES);
    unsigned deferredFrameSize = ppcGetDeferredFrameSizeForSaveArea(static_cast<unsigned>(framePointerOffset),
                                                                    saveAreaSize,
                                                                    static_cast<unsigned>(framePointerOffset));
    if (deferredFrameSize != 0)
    {
        genStackPointerAdjustment(deferredFrameSize, REG_TMP_0, nullptr, /* reportUnwindData */ true);

        frameSize += static_cast<int>(deferredFrameSize);
        framePointerOffset -= static_cast<int>(deferredFrameSize);
        linkRegisterOffset -= static_cast<int>(deferredFrameSize);
        calleeSavedOffset -= static_cast<int>(deferredFrameSize);
    }

    if (!emitter::isValidSimm16(calleeSavedOffset) || (calleeSavedOffset > 2047))
    {
        NYI_POWERPC64("large funclet callee-saved offset");
    }

    genRestoreCalleeSavedRegistersHelp(maskSaveRegs, REG_SPBASE, calleeSavedOffset, /* reportUnwindData */ true);

    GetEmitter()->emitIns_R_R_I(INS_ld, EA_PTRSIZE, REG_R0, REG_SPBASE, linkRegisterOffset);
    GetEmitter()->emitIns_R_R(INS_mtlr, EA_PTRSIZE, REG_R0, REG_R0);

    GetEmitter()->emitIns_R_R_I(INS_ld, EA_PTRSIZE, REG_FPBASE, REG_SPBASE, framePointerOffset);
    m_compiler->unwindSaveReg(REG_FPBASE, framePointerOffset);

    genStackPointerAdjustment(-frameSize, REG_TMP_0, nullptr, /* reportUnwindData */ true);

    GetEmitter()->emitIns(INS_blr);
    m_compiler->unwindReturn(REG_NA);

    m_compiler->unwindEndEpilog();
}

void CodeGen::genCaptureFuncletPrologEpilogInfo()
{
    if (!m_compiler->ehAnyFunclets())
    {
        return;
    }

    assert(isFramePointerUsed());
    assert(m_compiler->lvaDoneFrameLayout == Compiler::FINAL_FRAME_LAYOUT);

    regMaskTP rsMaskSaveRegs = regSet.rsMaskCalleeSaved;

    int funcletFrameSize   = m_compiler->lvaOutgoingArgSpaceSize;
    int framePointerOffset = funcletFrameSize;
    int linkRegisterOffset = framePointerOffset + PPC_FRAME_POINTER_SAVE_SIZE;
    int calleeSavedOffset  = linkRegisterOffset + PPC_LINK_REGISTER_SAVE_SIZE;

    genFuncletInfo.fiSP_to_CalleeSaved_delta = calleeSavedOffset;

    funcletFrameSize = calleeSavedOffset + (genCountBits(rsMaskSaveRegs) * REGSIZE_BYTES);

    int deltaPSP = -TARGET_POINTER_SIZE;
    if ((m_compiler->lvaMonAcquired != BAD_VAR_NUM) && !m_compiler->opts.IsOSR())
    {
        deltaPSP -= TARGET_POINTER_SIZE;
    }

    funcletFrameSize = funcletFrameSize - deltaPSP;
    funcletFrameSize = roundUp(static_cast<unsigned>(funcletFrameSize), STACK_ALIGN);

    genFuncletInfo.fiSpDelta  = -funcletFrameSize;
    genFuncletInfo.fiSaveRegs = rsMaskSaveRegs;

#ifdef DEBUG
    if (verbose)
    {
        printf("\n");
        printf("Funclet prolog / epilog info\n");
        printf("                        Save regs: ");
        dspRegMask(genFuncletInfo.fiSaveRegs);
        printf("\n");
        printf("  SP to CalleeSaved location delta: %d\n", genFuncletInfo.fiSP_to_CalleeSaved_delta);
        printf("                       SP delta: %d\n", genFuncletInfo.fiSpDelta);
    }
    assert(genFuncletInfo.fiSP_to_CalleeSaved_delta >= 0);
#endif // DEBUG
}

void CodeGen::genEmitGSCookieCheck(bool tailCall)
{
    noway_assert(m_compiler->gsGlobalSecurityCookieAddr || m_compiler->gsGlobalSecurityCookieVal);

    regMaskTP tmpRegs    = genGetGSCookieTempRegs(tailCall);
    regNumber regGSConst = genFirstRegNumFromMaskAndToggle(tmpRegs);
    regNumber regGSValue = genFirstRegNumFromMaskAndToggle(tmpRegs);

    if (m_compiler->gsGlobalSecurityCookieAddr == nullptr)
    {
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, regGSConst, m_compiler->gsGlobalSecurityCookieVal);
    }
    else
    {
        emitAttr addrAttr = m_compiler->opts.compReloc ? EA_HANDLE_CNS_RELOC : EA_PTRSIZE;
        instGen_Set_Reg_To_Imm(addrAttr, regGSConst,
                               reinterpret_cast<ssize_t>(m_compiler->gsGlobalSecurityCookieAddr));
        GetEmitter()->emitIns_R_R_I(INS_ld, EA_PTRSIZE, regGSConst, regGSConst, 0);
    }

    regNumber baseReg = REG_NA;
    int       offset  = ppcGetLclFrameOffset(m_compiler, m_compiler->lvaGSSecurityCookie, 0, &baseReg);
    genInstrWithConstant(INS_ld, EA_PTRSIZE, regGSValue, baseReg, offset, regGSValue);

    GetEmitter()->emitIns_R_R(INS_cmpd, EA_PTRSIZE, regGSConst, regGSValue);

    BasicBlock* gsCheckBlk = genCreateTempLabel();
    GetEmitter()->emitIns_J(INS_beq, gsCheckBlk);

    genEmitHelperCall(CORINFO_HELP_FAIL_FAST, 0, EA_UNKNOWN);
    genDefineTempLabel(gsCheckBlk);
}

void CodeGen::genJmpPlaceVarArgs()
{
    NYI_POWERPC64("genJmpPlaceVarArgs");
}

void CodeGen::genCallFinally(BasicBlock* block)
{
    assert(block->KindIs(BBJ_CALLFINALLY));

    BasicBlock* const nextBlock = block->Next();

    if (block->HasFlag(BBF_RETLESS_CALL))
    {
        GetEmitter()->emitIns_J(INS_bl, block->GetTarget());

        if ((nextBlock == nullptr) || !BasicBlock::sameEHRegion(block, nextBlock))
        {
            instGen(INS_trap);
        }

        return;
    }

    GetEmitter()->emitDisableGC();
    GetEmitter()->emitIns_J(INS_bl, block->GetTarget());

    BasicBlock* const finallyContinuation = nextBlock->GetFinallyContinuation();
    if (nextBlock->NextIs(finallyContinuation) && !m_compiler->fgInDifferentRegions(nextBlock, finallyContinuation))
    {
        instGen(INS_nop);
    }
    else
    {
        inst_JMP(EJ_jmp, finallyContinuation);
    }

    GetEmitter()->emitEnableGC();
}

void CodeGen::genEHCatchRet(BasicBlock* block)
{
    GetEmitter()->emitIns_R_L(INS_addi, EA_PTRSIZE, block->GetTarget(), REG_INTRET);
}

void CodeGen::genIntCastOverflowCheck(GenTreeCast* cast, const GenIntCastDesc& desc, regNumber reg)
{
    regNumber tempReg = internalRegisters.GetSingle(cast);

    auto shiftRight = [=](unsigned shift) {
        assert(shift < 64);
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, REG_R0, shift);
        GetEmitter()->emitIns_R_R_R(INS_srd, EA_PTRSIZE, tempReg, reg, REG_R0);
    };

    switch (desc.CheckKind())
    {
        case GenIntCastDesc::CHECK_POSITIVE:
            if (desc.CheckSrcSize() == 4)
            {
                GetEmitter()->emitIns_R_R(INS_extsw, EA_PTRSIZE, tempReg, reg);
                reg = tempReg;
            }
            genJumpToThrowHlpBlk_la(SCK_OVERFLOW, INS_blt, reg);
            break;

        case GenIntCastDesc::CHECK_UINT_RANGE:
            shiftRight(32);
            genJumpToThrowHlpBlk_la(SCK_OVERFLOW, INS_bne, tempReg);
            break;

        case GenIntCastDesc::CHECK_POSITIVE_INT_RANGE:
            shiftRight(31);
            genJumpToThrowHlpBlk_la(SCK_OVERFLOW, INS_bne, tempReg);
            break;

        case GenIntCastDesc::CHECK_INT_RANGE:
            GetEmitter()->emitIns_R_R(INS_extsw, EA_PTRSIZE, tempReg, reg);
            genJumpToThrowHlpBlk_la(SCK_OVERFLOW, INS_bne, tempReg, nullptr, reg);
            break;

        default:
        {
            assert(desc.CheckKind() == GenIntCastDesc::CHECK_SMALL_INT_RANGE);

            const unsigned castSize = genTypeSize(cast->gtCastType);
            assert((castSize == 1) || (castSize == 2));

            if (desc.CheckSmallIntMin() == 0)
            {
                const bool     isDstSigned = !varTypeIsUnsigned(cast->gtCastType);
                const unsigned checkBits   = (castSize * BITS_PER_BYTE) - (isDstSigned ? 1 : 0);

                shiftRight(checkBits);
                genJumpToThrowHlpBlk_la(SCK_OVERFLOW, INS_bne, tempReg);
            }
            else
            {
                instruction extend = (castSize == 1) ? INS_extsb : INS_extsh;
                GetEmitter()->emitIns_R_R(extend, EA_PTRSIZE, tempReg, reg);
                genJumpToThrowHlpBlk_la(SCK_OVERFLOW, INS_bne, tempReg, nullptr, reg);
            }
            break;
        }
    }
}

void CodeGen::genIntToIntCast(GenTreeCast* cast)
{
    genConsumeRegs(cast->gtGetOp1());

    GenIntCastDesc desc(cast);
    if (desc.CheckKind() != GenIntCastDesc::CHECK_NONE)
    {
        genIntCastOverflowCheck(cast, desc, cast->gtGetOp1()->GetRegNum());
    }

    emitter*        emit   = GetEmitter();
    const regNumber srcReg = cast->gtGetOp1()->GetRegNum();
    const regNumber dstReg = cast->GetRegNum();

    assert(genIsValidIntReg(srcReg));
    assert(genIsValidIntReg(dstReg));

    switch (desc.ExtendKind())
    {
        case GenIntCastDesc::ZERO_EXTEND_SMALL_INT:
        {
            unsigned clearBits = 64 - (desc.ExtendSrcSize() * BITS_PER_BYTE);
            emit->emitIns_R_R_I(INS_clrldi, EA_PTRSIZE, dstReg, srcReg, clearBits);
            break;
        }

        case GenIntCastDesc::SIGN_EXTEND_SMALL_INT:
        {
            instruction extend = (desc.ExtendSrcSize() == 1) ? INS_extsb : INS_extsh;
            emit->emitIns_R_R(extend, EA_PTRSIZE, dstReg, srcReg);
            break;
        }

        case GenIntCastDesc::ZERO_EXTEND_INT:
            emit->emitIns_R_R_I(INS_clrldi, EA_PTRSIZE, dstReg, srcReg, 32);
            break;

        case GenIntCastDesc::SIGN_EXTEND_INT:
            emit->emitIns_R_R(INS_extsw, EA_PTRSIZE, dstReg, srcReg);
            break;

        default:
            assert(desc.ExtendKind() == GenIntCastDesc::COPY);
            emit->emitIns_Mov(emitActualTypeSize(cast), dstReg, srcReg, true);
            break;
    }

    genProduceReg(cast);
}

void CodeGen::genFloatToFloatCast(GenTree* treeNode)
{
    assert(treeNode->OperIs(GT_CAST));
    assert(!treeNode->gtOverflow());

    GenTree* op1 = treeNode->AsCast()->CastOp();
    assert(varTypeIsFloating(op1));
    assert(varTypeIsFloating(treeNode));

    regNumber srcReg = genConsumeReg(op1);
    regNumber dstReg = treeNode->GetRegNum();

    assert(genIsValidFloatReg(srcReg));
    assert(genIsValidFloatReg(dstReg));

    var_types srcType = op1->TypeGet();
    var_types dstType = treeNode->CastToType();

    if ((srcType == TYP_DOUBLE) && (dstType == TYP_FLOAT))
    {
        GetEmitter()->emitIns_R_R(INS_frsp, EA_4BYTE, dstReg, srcReg);
    }
    else if (dstReg != srcReg)
    {
        GetEmitter()->emitIns_Mov(emitActualTypeSize(treeNode), dstReg, srcReg, true);
    }

    genProduceReg(treeNode);
}

void CodeGen::genFloatToIntCast(GenTree* treeNode)
{
    assert(treeNode->OperIs(GT_CAST));
    assert(!treeNode->gtOverflow());

    regNumber targetReg = treeNode->GetRegNum();
    assert(genIsValidIntReg(targetReg));

    GenTree* op1 = treeNode->AsCast()->CastOp();
    assert(!op1->isContained());
    assert(genIsValidFloatReg(op1->GetRegNum()));

    var_types dstType = treeNode->AsCast()->CastToType();
    var_types srcType = genActualType(op1->TypeGet());
    assert(varTypeIsFloating(srcType) && !varTypeIsFloating(dstType));

    emitAttr dstSize = emitActualTypeSize(dstType);
    noway_assert((dstSize == EA_4BYTE) || (dstSize == EA_8BYTE));

    bool isUnsigned = varTypeIsUnsigned(dstType);

    genConsumeOperands(treeNode->AsOp());

    regNumber tempReg = internalRegisters.Extract(treeNode, RBM_ALLFLOAT);
    assert(genIsValidFloatReg(tempReg));

    instruction convertIns = INS_fctiwz;
    if (isUnsigned)
    {
        convertIns = INS_fctiduz;
    }
    else if (dstSize == EA_8BYTE)
    {
        convertIns = INS_fctidz;
    }

    GetEmitter()->emitIns_R_R(convertIns, emitActualTypeSize(srcType), tempReg, op1->GetRegNum());
    GetEmitter()->emitIns_R_R(INS_mffprd, dstSize, targetReg, tempReg);

    if (dstSize == EA_4BYTE)
    {
        if (isUnsigned)
        {
            assert(dstType == TYP_UINT);

            regNumber lowReg = internalRegisters.Extract(treeNode, RBM_ALLINT);
            assert(genIsValidIntReg(lowReg));

            GetEmitter()->emitIns_R_R_I(INS_clrldi, EA_8BYTE, lowReg, targetReg, 32);
            GetEmitter()->emitIns_R_R(INS_cmpld, EA_8BYTE, targetReg, lowReg);

            BasicBlock* doneLabel = genCreateTempLabel();
            GetEmitter()->emitIns_J(INS_beq, doneLabel);

            instGen_Set_Reg_To_Imm(EA_8BYTE, targetReg, -1);
            GetEmitter()->emitIns_R_R_I(INS_clrldi, EA_8BYTE, targetReg, targetReg, 32);

            genDefineTempLabel(doneLabel);
        }
        else
        {
            GetEmitter()->emitIns_R_R(INS_extsw, dstSize, targetReg, targetReg);
        }
    }

    genProduceReg(treeNode);
}

void CodeGen::genIntToFloatCast(GenTree* treeNode)
{
    assert(treeNode->OperIs(GT_CAST));
    assert(!treeNode->gtOverflow());

    regNumber targetReg = treeNode->GetRegNum();
    assert(genIsValidFloatReg(targetReg));

    GenTree* op1 = treeNode->AsCast()->CastOp();
    assert(!op1->isContained());
    assert(genIsValidIntReg(op1->GetRegNum()));

    var_types dstType = treeNode->AsCast()->CastToType();
    var_types srcType = genActualType(op1->TypeGet());
    assert(!varTypeIsFloating(srcType) && varTypeIsFloating(dstType));

    bool     isUnsigned = treeNode->IsUnsigned();
    emitAttr srcSize    = EA_ATTR(genTypeSize(srcType));
    noway_assert((srcSize == EA_4BYTE) || (srcSize == EA_8BYTE));

    genConsumeOperands(treeNode->AsOp());

    regNumber sourceReg = op1->GetRegNum();
    if (srcSize == EA_4BYTE)
    {
        if (isUnsigned)
        {
            GetEmitter()->emitIns_R_R_I(INS_clrldi, EA_8BYTE, REG_R0, sourceReg, 32);
        }
        else
        {
            GetEmitter()->emitIns_R_R(INS_extsw, EA_8BYTE, REG_R0, sourceReg);
        }
        sourceReg = REG_R0;
    }

    GetEmitter()->emitIns_R_R(INS_mtfprd, EA_8BYTE, targetReg, sourceReg);
    instruction convertIns = INS_fcfid;
    if (dstType == TYP_FLOAT)
    {
        convertIns = isUnsigned ? INS_fcfidus : INS_fcfids;
    }
    else if (isUnsigned)
    {
        convertIns = INS_fcfidu;
    }

    GetEmitter()->emitIns_R_R(convertIns, emitActualTypeSize(dstType), targetReg, targetReg);

    genProduceReg(treeNode);
}

void CodeGen::genSimpleReturn(GenTree* treeNode)
{
    assert(treeNode->OperIs(GT_RETURN) || treeNode->OperIs(GT_RETFILT));

    GenTree* op1 = treeNode->gtGetOp1();
    if (op1 == nullptr)
    {
        return;
    }

    regNumber retReg = varTypeUsesFloatReg(treeNode) ? REG_FLOATRET : REG_INTRET;
    if (op1->GetRegNum() != retReg)
    {
        GetEmitter()->emitIns_Mov(emitActualTypeSize(treeNode), retReg, op1->GetRegNum(), true);
    }
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
    if (EA_IS_CNS_RELOC(size))
    {
        assert(m_compiler->opts.compReloc);
        assert(reg != REG_R2);

        emitAttr relocAttr = EA_HANDLE_CNS_RELOC;
        if (EA_IS_CNS_TLSGD_RELOC(size))
        {
            relocAttr = EA_SET_FLG(relocAttr, EA_CNS_TLSGD_RELOC);
            GetEmitter()->emitIns_R_R_I(INS_addis, relocAttr, reg, REG_R2, imm);
            GetEmitter()->emitIns_R_R_I(INS_ld, relocAttr, reg, reg, imm);
            GetEmitter()->emitIns_R_R_R_I(INS_add, relocAttr, reg, reg, REG_TP, imm);
            return;
        }

        if (EA_IS_BYREF(size))
        {
            relocAttr = EA_SET_FLG(relocAttr, EA_BYREF_FLG);
        }

        GetEmitter()->emitIns_R_R_I(INS_addis, relocAttr, reg, REG_R2, imm);
        GetEmitter()->emitIns_R_R_I(INS_addi, relocAttr, reg, reg, imm);
        return;
    }

    auto signExtend16 = [](uint64_t value) -> ssize_t {
        ssize_t part = static_cast<ssize_t>(value & 0xFFFF);
        return (part >= 0x8000) ? (part - 0x10000) : part;
    };

    auto unsigned16 = [](uint64_t value) -> ssize_t {
        return static_cast<ssize_t>(value & 0xFFFF);
    };

    if (emitter::isValidSimm16(imm))
    {
        GetEmitter()->emitIns_R_R_I(INS_addi, size, reg, REG_R0, imm);
        return;
    }

    const uint64_t value = static_cast<uint64_t>(imm);

    if ((imm >= INT32_MIN) && (imm <= INT32_MAX))
    {
        ssize_t hi = signExtend16(value >> 16);
        ssize_t lo = unsigned16(value);

        GetEmitter()->emitIns_R_R_I(INS_addis, size, reg, REG_R0, hi);
        if (lo != 0)
        {
            GetEmitter()->emitIns_R_R_I(INS_ori, size, reg, reg, lo);
        }
        return;
    }

    if ((imm >= 0) && (value <= UINT32_MAX))
    {
        GetEmitter()->emitIns_R_R_I(INS_addi, size, reg, REG_R0, 0);

        ssize_t hi = unsigned16(value >> 16);
        ssize_t lo = unsigned16(value);
        if (hi != 0)
        {
            GetEmitter()->emitIns_R_R_I(INS_oris, size, reg, reg, hi);
        }
        if (lo != 0)
        {
            GetEmitter()->emitIns_R_R_I(INS_ori, size, reg, reg, lo);
        }
        return;
    }

    if ((imm >= -(1LL << 47)) && (imm < (1LL << 47)))
    {
        GetEmitter()->emitIns_R_R_I(INS_addi, size, reg, REG_R0, signExtend16(value >> 32));
        GetEmitter()->emitIns_R_R_I(INS_sldi, size, reg, reg, 32);

        ssize_t hi = unsigned16(value >> 16);
        ssize_t lo = unsigned16(value);
        if (hi != 0)
        {
            GetEmitter()->emitIns_R_R_I(INS_oris, size, reg, reg, hi);
        }
        if (lo != 0)
        {
            GetEmitter()->emitIns_R_R_I(INS_ori, size, reg, reg, lo);
        }
        return;
    }

    GetEmitter()->emitIns_R_R_I(INS_addis, size, reg, REG_R0, signExtend16(value >> 48));

    ssize_t next = unsigned16(value >> 32);
    if (next != 0)
    {
        GetEmitter()->emitIns_R_R_I(INS_ori, size, reg, reg, next);
    }

    GetEmitter()->emitIns_R_R_I(INS_sldi, size, reg, reg, 32);

    ssize_t hi = unsigned16(value >> 16);
    ssize_t lo = unsigned16(value);
    if (hi != 0)
    {
        GetEmitter()->emitIns_R_R_I(INS_oris, size, reg, reg, hi);
    }
    if (lo != 0)
    {
        GetEmitter()->emitIns_R_R_I(INS_ori, size, reg, reg, lo);
    }
}

// clang-format off
const GenConditionDesc GenConditionDesc::map[32]
{
    { },       // NONE
    { },       // 1
    { EJ_lt }, // SLT
    { EJ_le }, // SLE
    { EJ_ge }, // SGE
    { EJ_gt }, // SGT
    { },       // S
    { },       // NS

    { EJ_eq }, // EQ
    { EJ_ne }, // NE
    { EJ_lt }, // ULT
    { EJ_le }, // ULE
    { EJ_ge }, // UGE
    { EJ_gt }, // UGT
    { },       // C
    { },       // NC
};
// clang-format on

#endif // TARGET_POWERPC64
