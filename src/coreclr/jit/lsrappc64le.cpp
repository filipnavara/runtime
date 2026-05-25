// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "jitpch.h"
#ifdef _MSC_VER
#pragma hdrstop
#endif

#if defined(TARGET_POWERPC64)

#include "jit.h"
#include "sideeffects.h"
#include "lower.h"
#include "codegen.h"
#include "lsra.h"

static bool ppc64leOffsetFitsInstruction(instruction ins, ssize_t offset)
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
            // Codegen handles unaligned signed-16 displacements as lwz+extsw,
            // so LSRA only needs an address temp when the displacement does
            // not fit the D-form signed-16 field at all.
            return true;

        default:
            return true;
    }
}

static bool ppc64leNeedsLclOffsetTemp(Compiler* compiler, instruction ins, GenTreeLclVarCommon* lclNode)
{
    bool fpBased = false;
    int  offset  = compiler->lvaFrameAddress(lclNode->GetLclNum(), &fpBased) + lclNode->GetLclOffs();
    if (lclNode->GetLclNum() == compiler->lvaOutgoingArgSpaceVar)
    {
        offset += FIRST_ARG_STACK_OFFS;
    }
    return !ppc64leOffsetFitsInstruction(ins, offset);
}

static bool ppc64leOffsetRangeFitsSimm16(int offset, unsigned size)
{
    assert(size > 0);
    ssize_t lastOffset = static_cast<ssize_t>(offset) + static_cast<ssize_t>(size) - 1;
    return emitter::isValidSimm16(offset) && emitter::isValidSimm16(lastOffset);
}

static bool ppc64leContainedAddrNeedsLargeOffsetTemp(Compiler* compiler, GenTree* addr, unsigned size)
{
    if (!addr->isContained())
    {
        return false;
    }

    int offset = 0;
    if (addr->OperIsAddrMode())
    {
        offset = addr->AsAddrMode()->Offset();
    }
    else
    {
        assert(addr->OperIs(GT_LCL_ADDR));

        bool fpBased = false;
        offset = compiler->lvaFrameAddress(addr->AsLclVarCommon()->GetLclNum(), &fpBased) +
                 addr->AsLclVarCommon()->GetLclOffs();
    }

    return !ppc64leOffsetRangeFitsSimm16(offset, size) || !ppc64leOffsetFitsInstruction(INS_std, offset);
}

int LinearScan::BuildNode(GenTree* tree)
{
    assert(!tree->isContained());
    clearBuildState();

    switch (tree->OperGet())
    {
        case GT_LCL_VAR:
        {
            if (checkContainedOrCandidateLclVar(tree->AsLclVar()))
            {
                return 0;
            }

            LclVarDsc* varDsc = m_compiler->lvaGetDesc(tree->AsLclVar());
            var_types targetType = varDsc->GetRegisterType(tree->AsLclVar());
            if (!varDsc->lvIsRegCandidate() && !tree->AsLclVar()->IsMultiReg() &&
                ((tree->gtFlags & GTF_SPILLED) == 0) &&
                ppc64leNeedsLclOffsetTemp(m_compiler, m_compiler->codeGen->ins_Load(targetType), tree->AsLclVar()))
            {
                buildInternalIntRegisterDefForNode(tree);
                buildInternalRegisterUses();
            }

            BuildDef(tree);
            return 0;
        }

        case GT_LCL_FLD:
            if (!tree->TypeIs(TYP_STRUCT) &&
                ppc64leNeedsLclOffsetTemp(m_compiler, m_compiler->codeGen->ins_Load(tree->TypeGet()), tree->AsLclFld()))
            {
                buildInternalIntRegisterDefForNode(tree);
                buildInternalRegisterUses();
            }

            BuildDef(tree);
            return 0;

        case GT_LCL_ADDR:
            BuildDef(tree);
            return 0;

        case GT_LEA:
        {
            GenTreeAddrMode* lea = tree->AsAddrMode();
            assert(lea->HasBase() || lea->HasIndex());

            int srcCount = 0;

            if (lea->HasBase())
            {
                BuildUse(lea->Base());
                srcCount++;
            }

            if (lea->HasIndex())
            {
                BuildUse(lea->Index());
                srcCount++;
            }

            if (!emitter::isValidSimm16(lea->Offset()) || (lea->HasBase() && lea->HasIndex() && (lea->gtScale > 1)))
            {
                buildInternalIntRegisterDefForNode(tree);
                buildInternalRegisterUses();
            }

            BuildDef(tree);
            return srcCount;
        }

        case GT_INDEX_ADDR:
        {
            int srcCount = BuildBinaryUses(tree->AsOp());
            buildInternalIntRegisterDefForNode(tree);
            buildInternalRegisterUses();
            BuildDef(tree);
            return srcCount;
        }

        case GT_STORE_LCL_VAR:
        case GT_STORE_LCL_FLD:
            return BuildStoreLoc(tree->AsLclVarCommon());

        case GT_STOREIND:
        {
            if (m_compiler->codeGen->gcInfo.gcIsWriteBarrierStoreIndNode(tree->AsStoreInd()))
            {
                return BuildGCWriteBarrier(tree);
            }

            int srcCount = BuildIndir(tree->AsIndir());
            if (!tree->gtGetOp2()->isContained())
            {
                BuildUse(tree->gtGetOp2());
                srcCount++;
            }
            return srcCount;
        }

        case GT_NULLCHECK:
        case GT_IND:
            return BuildIndir(tree->AsIndir());

        case GT_CATCH_ARG:
            BuildDef(tree, RBM_EXCEPTION_OBJECT.GetIntRegSet());
            return 0;

        case GT_ASYNC_CONTINUATION:
            BuildDef(tree, RBM_ASYNC_CONTINUATION_RET.GetIntRegSet());
            return 0;

        case GT_CNS_DBL:
        {
            buildInternalIntRegisterDefForNode(tree);
            buildInternalRegisterUses();

            RefPosition* def               = BuildDef(tree);
            def->getInterval()->isConstant = true;
            return 0;
        }

        case GT_BITCAST:
        {
            GenTree* op1      = tree->gtGetOp1();
            int      srcCount = BuildOperandUses(op1);

            if ((genTypeSize(tree) == 4) && (varTypeUsesFloatReg(tree) != varTypeUsesFloatReg(op1)))
            {
                if (varTypeUsesFloatReg(tree))
                {
                    buildInternalIntRegisterDefForNode(tree);
                }
                else
                {
                    buildInternalFloatRegisterDefForNode(tree);
                }
                buildInternalRegisterUses();
            }

            BuildDef(tree);
            return srcCount;
        }

        case GT_CAST:
        {
            GenTreeCast* cast        = tree->AsCast();
            int          srcCount    = BuildCastUses(cast, RBM_NONE);
            bool         hasInternal = false;

            if (varTypeIsIntegral(tree) && varTypeIsIntegral(cast->CastOp()) &&
                (CodeGen::GenIntCastDesc(cast).CheckKind() != CodeGen::GenIntCastDesc::CHECK_NONE))
            {
                buildInternalIntRegisterDefForNode(tree);
                hasInternal = true;
            }

            if (varTypeIsIntegral(tree) && varTypeIsFloating(cast->CastOp()))
            {
                buildInternalFloatRegisterDefForNode(tree);
                if (tree->AsCast()->CastToType() == TYP_UINT)
                {
                    buildInternalIntRegisterDefForNode(tree);
                    setInternalRegsDelayFree = true;
                }
                hasInternal = true;
            }

            if (hasInternal)
            {
                buildInternalRegisterUses();
            }

            BuildDef(tree);
            return srcCount;
        }

        case GT_DIV:
        case GT_UDIV:
        case GT_MOD:
        case GT_UMOD:
        {
            int srcCount = BuildBinaryUses(tree->AsOp());

            bool needsInternalReg = tree->OperIs(GT_MOD, GT_UMOD);
            if (tree->OperIs(GT_DIV) &&
                ((tree->OperExceptions(m_compiler) & ExceptionSetFlags::ArithmeticException) !=
                 ExceptionSetFlags::None))
            {
                needsInternalReg = true;
            }

            if (needsInternalReg)
            {
                buildInternalIntRegisterDefForNode(tree);
                buildInternalRegisterUses();
            }
            BuildDef(tree);
            return srcCount;
        }

        case GT_ADD:
        case GT_SUB:
        {
            int srcCount = 0;
            if (tree->gtOverflow())
            {
                setDelayFree(BuildUse(tree->gtGetOp1()));
                setDelayFree(BuildUse(tree->gtGetOp2()));
                srcCount = 2;
            }
            else
            {
                srcCount = BuildBinaryUses(tree->AsOp());
            }

            if (tree->gtOverflow() && !tree->IsUnsigned())
            {
                buildInternalIntRegisterDefForNode(tree);
                buildInternalIntRegisterDefForNode(tree);
                setInternalRegsDelayFree = true;
                buildInternalRegisterUses();
            }
            BuildDef(tree);
            return srcCount;
        }

        case GT_MUL:
        {
            int srcCount = BuildBinaryUses(tree->AsOp());
            if (!varTypeIsFloating(tree) && tree->gtOverflow())
            {
                buildInternalIntRegisterDefForNode(tree);
                if (!tree->IsUnsigned())
                {
                    buildInternalIntRegisterDefForNode(tree);
                }
                setInternalRegsDelayFree = true;
                buildInternalRegisterUses();
            }
            BuildDef(tree);
            return srcCount;
        }

        case GT_MULHI:
        {
            int srcCount = BuildBinaryUses(tree->AsOp());
            BuildDef(tree);
            return srcCount;
        }

        case GT_INTRINSIC:
        {
            GenTree* op1 = tree->gtGetOp1();
            noway_assert((tree->AsIntrinsic()->gtIntrinsicName == NI_System_Math_Abs) ||
                         (tree->AsIntrinsic()->gtIntrinsicName == NI_System_Math_Sqrt));
            assert(varTypeIsFloating(tree));
            assert(op1->TypeIs(tree->TypeGet()));

            BuildUse(op1);
            BuildDef(tree);
            return 1;
        }

        case GT_INC_SATURATE:
        {
            RefPosition* use = BuildUse(tree->gtGetOp1());
            setDelayFree(use);
            BuildDef(tree);
            return 1;
        }

        case GT_ROL:
        case GT_ROR:
        {
            int srcCount = BuildBinaryUses(tree->AsOp());
            if (tree->OperIs(GT_ROR) && !tree->gtGetOp2()->isContained())
            {
                buildInternalIntRegisterDefForNode(tree);
                buildInternalRegisterUses();
            }
            BuildDef(tree);
            return srcCount;
        }

        case GT_BSWAP:
        case GT_BSWAP16:
        {
            RefPosition* use      = BuildUse(tree->gtGetOp1());
            int          srcCount = 1;
            setDelayFree(use);
            buildInternalIntRegisterDefForNode(tree);
            buildInternalRegisterUses();
            BuildDef(tree);
            return srcCount;
        }

        case GT_CMPXCHG:
        {
            GenTreeCmpXchg* cmpXchg = tree->AsCmpXchg();

            int srcCount = 1;
            assert(!cmpXchg->Addr()->isContained());
            setDelayFree(BuildUse(cmpXchg->Addr()));

            GenTree* data = cmpXchg->Data();
            if (!data->isContained())
            {
                srcCount++;
                setDelayFree(BuildUse(data));
            }
            else
            {
                unreached();
            }

            GenTree* comparand = cmpXchg->Comparand();
            if (!comparand->isContained())
            {
                srcCount++;
                setDelayFree(BuildUse(comparand));
            }
            else
            {
                unreached();
            }

            BuildDef(tree);
            return srcCount;
        }

        case GT_XORR:
        case GT_XAND:
        case GT_XADD:
        case GT_XCHG:
        {
            int srcCount = 1;

            GenTree* addr = tree->gtGetOp1();
            assert(!addr->isContained());
            setDelayFree(BuildUse(addr));

            GenTree* data = tree->gtGetOp2();
            if (!data->isContained())
            {
                srcCount++;
                setDelayFree(BuildUse(data));
            }
            else
            {
                unreached();
            }

            const bool hasReturnValue = !tree->TypeIs(TYP_VOID);
            if (!hasReturnValue)
            {
                buildInternalIntRegisterDefForNode(tree);
            }

            if (!tree->OperIs(GT_XCHG))
            {
                buildInternalIntRegisterDefForNode(tree);
            }

            if (!hasReturnValue || !tree->OperIs(GT_XCHG))
            {
                setInternalRegsDelayFree = true;
                buildInternalRegisterUses();
            }

            if (hasReturnValue)
            {
                BuildDef(tree);
            }

            return srcCount;
        }

        case GT_EQ:
        case GT_NE:
        case GT_LT:
        case GT_LE:
        case GT_GE:
        case GT_GT:
        case GT_JCMP:
            return BuildCmp(tree);

        case GT_BOUNDS_CHECK:
        {
            GenTreeBoundsChk* node       = tree->AsBoundsChk();
            var_types         indexType  = genActualType(node->GetIndex());
            var_types         lengthType = genActualType(node->GetArrayLength());

            if ((indexType == TYP_INT) && (lengthType == TYP_LONG))
            {
                buildInternalIntRegisterDefForNode(tree);
            }
            if ((lengthType == TYP_INT) && (indexType == TYP_LONG))
            {
                buildInternalIntRegisterDefForNode(tree);
            }

            buildInternalRegisterUses();

            int srcCount = BuildOperandUses(node->GetIndex());
            srcCount += BuildOperandUses(node->GetArrayLength());
            return srcCount;
        }

        case GT_RETURN:
        {
            int       srcCount = BuildReturn(tree);
            regMaskTP killMask = getKillSetForReturn(tree);
            BuildKills(tree, killMask);
            return srcCount;
        }

        case GT_RETURNTRAP:
        {
            BuildUse(tree->gtGetOp1());
            regMaskTP killMask = m_compiler->compHelperCallKillSet(CORINFO_HELP_STOP_FOR_GC);
            BuildKills(tree, killMask);
            return 1;
        }

        case GT_PATCHPOINT:
        {
            int srcCount = BuildOperandUses(tree->gtGetOp1(), RBM_ARG_0.GetIntRegSet());
            srcCount += BuildOperandUses(tree->gtGetOp2(), RBM_ARG_1.GetIntRegSet());
            BuildKills(tree, m_compiler->compHelperCallKillSet(CORINFO_HELP_PATCHPOINT));
            return srcCount;
        }

        case GT_PATCHPOINT_FORCED:
        {
            int srcCount = BuildOperandUses(tree->gtGetOp1(), RBM_ARG_0.GetIntRegSet());
            BuildKills(tree, m_compiler->compHelperCallKillSet(CORINFO_HELP_PATCHPOINT_FORCED));
            return srcCount;
        }

        case GT_STORE_BLK:
            return BuildBlockStore(tree->AsBlk());

        case GT_LCLHEAP:
        {
            assert(tree->IsValue());

            int  srcCount      = 0;
            bool needExtraTemp = (m_compiler->lvaOutgoingArgSpaceSize > 0);

            GenTree* size = tree->gtGetOp1();
            if (size->IsCnsIntOrI())
            {
                assert(size->isContained());

                size_t sizeVal = size->AsIntCon()->gtIconVal;
                if (sizeVal != 0)
                {
                    sizeVal = AlignUp(sizeVal, STACK_ALIGN);

                    if (sizeVal <= (REGSIZE_BYTES * 2 * 4))
                    {
                        // No internal registers needed.
                    }
                    else if (!m_compiler->info.compInitMem)
                    {
                        if (sizeVal < m_compiler->eeGetPageSize())
                        {
                            needExtraTemp |= !emitter::isValidSimm16(-static_cast<ssize_t>(sizeVal));
                        }
                        else
                        {
                            buildInternalIntRegisterDefForNode(tree);
                            buildInternalIntRegisterDefForNode(tree);
                            needExtraTemp = true;
                        }
                    }
                }
            }
            else
            {
                srcCount = 1;
                if (!m_compiler->info.compInitMem)
                {
                    buildInternalIntRegisterDefForNode(tree);
                    buildInternalIntRegisterDefForNode(tree);
                    needExtraTemp = true;
                }
            }

            if (needExtraTemp)
            {
                buildInternalIntRegisterDefForNode(tree);
            }

            if (!size->isContained())
            {
                BuildUse(size);
            }

            buildInternalRegisterUses();
            BuildDef(tree);
            return srcCount;
        }

        case GT_PUTARG_STK:
            return BuildPutArgStk(tree->AsPutArgStk());

        case GT_PUTARG_REG:
            return BuildPutArgReg(tree->AsUnOp());

        case GT_CALL:
            return BuildCall(tree->AsCall());

        case GT_SWITCH:
            noway_assert(!"Switch must be lowered at this point");
            return 0;

        case GT_JMPTABLE:
            BuildDef(tree);
            return 0;

        case GT_SWITCH_TABLE:
        {
            buildInternalIntRegisterDefForNode(tree);
            int srcCount = BuildBinaryUses(tree->AsOp());
            buildInternalRegisterUses();
            return srcCount;
        }

        default:
            return BuildSimple(tree);
    }
}

int LinearScan::BuildIndir(GenTreeIndir* indirTree)
{
    assert(!indirTree->TypeIs(TYP_STRUCT));

    instruction ins = INS_invalid;
    if (indirTree->OperIs(GT_STOREIND))
    {
        ins = m_compiler->codeGen->ins_Store(indirTree->TypeGet());
    }
    else
    {
        assert(indirTree->OperIs(GT_IND, GT_NULLCHECK));
        ins = m_compiler->codeGen->ins_Load(indirTree->TypeGet());
    }

    GenTree*       addr       = indirTree->Addr();
    const unsigned accessSize = indirTree->OperIs(GT_NULLCHECK) ? 1 : genTypeSize(indirTree);
    if ((addr->isContained() && ppc64leContainedAddrNeedsLargeOffsetTemp(m_compiler, addr, accessSize)) ||
        (!addr->isContained() && !ppc64leOffsetFitsInstruction(ins, indirTree->Offset())))
    {
        buildInternalIntRegisterDefForNode(indirTree);
    }

    int srcCount = BuildIndirUses(indirTree);

    buildInternalRegisterUses();

    if (!indirTree->OperIs(GT_STOREIND, GT_NULLCHECK))
    {
        BuildDef(indirTree);
    }

    return srcCount;
}

int LinearScan::BuildCall(GenTreeCall* call)
{
    bool                  hasMultiRegRetVal   = false;
    const ReturnTypeDesc* retTypeDesc         = nullptr;
    SingleTypeRegSet      singleDstCandidates = RBM_NONE;

    int srcCount = 0;
    int dstCount = 0;

    if (!call->TypeIs(TYP_VOID))
    {
        hasMultiRegRetVal = call->HasMultiRegRetVal();
        if (hasMultiRegRetVal)
        {
            retTypeDesc = call->GetReturnTypeDesc();
            dstCount    = retTypeDesc->GetReturnRegCount();
        }
        else
        {
            dstCount = 1;
        }
    }

    GenTree*         ctrlExpr           = call->gtControlExpr;
    SingleTypeRegSet ctrlExprCandidates = RBM_NONE;
    if (ctrlExpr != nullptr)
    {
        assert(!ctrlExpr->TypeIs(TYP_VOID));

        if (call->IsFastTailCall())
        {
            ctrlExprCandidates = allRegs(TYP_INT) & RBM_INT_CALLEE_TRASH.GetIntRegSet();
            if (m_compiler->getNeedsGSSecurityCookie())
            {
                ctrlExprCandidates &= ~m_compiler->codeGen->genGetGSCookieTempRegs(/* tailCall */ true).GetIntRegSet();
            }
            assert(ctrlExprCandidates != RBM_NONE);
        }

        if (call->GetIndirectionCellArgKind() != WellKnownArg::None)
        {
            // The indirection cell is passed in REG_R2R_INDIRECT_PARAM and must
            // remain live until the call. Keep the control expression in a
            // different register so codegen can also branch through r12 per
            // ELFv2.
            SingleTypeRegSet r2rIndirectParamReg = RBM_R2R_INDIRECT_PARAM.GetIntRegSet();
            ctrlExprCandidates =
                (ctrlExprCandidates == RBM_NONE ? allRegs(TYP_INT) : ctrlExprCandidates) & ~r2rIndirectParamReg;
            assert(ctrlExprCandidates != RBM_NONE);
        }

        if (ctrlExpr->isContainedIntOrIImmed())
        {
            buildInternalIntRegisterDefForNode(call);
        }
    }
    else if (call->IsR2ROrVirtualStubRelativeIndir())
    {
        SingleTypeRegSet candidates = allRegs(TYP_INT);
        if (call->IsFastTailCall())
        {
            candidates &= RBM_INT_CALLEE_TRASH.GetIntRegSet();
            assert(candidates != RBM_NONE);
        }

        SingleTypeRegSet indirectionCellReg =
            (call->GetIndirectionCellArgKind() == WellKnownArg::VirtualStubCell)
                ? m_compiler->virtualStubParamInfo->GetRegMask().GetIntRegSet()
                : RBM_R2R_INDIRECT_PARAM.GetIntRegSet();
        candidates &= ~indirectionCellReg;
        assert(candidates != RBM_NONE);

        buildInternalIntRegisterDefForNode(call, candidates);
    }

    RegisterType registerType = call->TypeGet();
    if (!hasMultiRegRetVal)
    {
        if (varTypeUsesFloatArgReg(registerType))
        {
            singleDstCandidates = RBM_FLOATRET.GetFloatRegSet();
        }
        else if (registerType == TYP_LONG)
        {
            singleDstCandidates = RBM_LNGRET.GetIntRegSet();
        }
        else
        {
            singleDstCandidates = RBM_INTRET.GetIntRegSet();
        }
    }

    srcCount += BuildCallArgUses(call);

    if ((ctrlExpr != nullptr) && !ctrlExpr->isContainedIntOrIImmed())
    {
        BuildUse(ctrlExpr, ctrlExprCandidates);
        srcCount++;
    }

    buildInternalRegisterUses();

    if (call->IsAsync() && m_compiler->compIsAsync() && !call->IsFastTailCall())
    {
        MarkAsyncContinuationBusyForCall(call);
    }

    regMaskTP killMask = getKillSetForCall(call);
    if (dstCount > 0)
    {
        if (hasMultiRegRetVal)
        {
            assert(retTypeDesc != nullptr);
            regMaskTP multiDstCandidates = retTypeDesc->GetABIReturnRegs(call->GetUnmanagedCallConv());
            assert(genCountBits(multiDstCandidates) > 0);
            BuildCallDefsWithKills(call, dstCount, multiDstCandidates, killMask);
        }
        else
        {
            assert(dstCount == 1);
            BuildDefWithKills(call, singleDstCandidates, killMask);
        }
    }
    else
    {
        BuildKills(call, killMask);
    }

    placedArgRegs      = RBM_NONE;
    numPlacedArgLocals = 0;
    return srcCount;
}

int LinearScan::BuildPutArgStk(GenTreePutArgStk* argNode)
{
    assert(argNode->OperIs(GT_PUTARG_STK));

    GenTree* src      = argNode->gtGetOp1();
    int      srcCount = 0;

    if (src->TypeIs(TYP_STRUCT))
    {
        if (src->OperIs(GT_FIELD_LIST))
        {
            assert(src->isContained());
            bool needsOffsetTmp = false;

            for (GenTreeFieldList::Use& use : src->AsFieldList()->Uses())
            {
                BuildUse(use.GetNode());
                srcCount++;

                bool fpBased = false;
                int  offset  = m_compiler->lvaFrameAddress(m_compiler->lvaOutgoingArgSpaceVar, &fpBased) +
                              static_cast<int>(argNode->getArgOffset() + use.GetOffset() + FIRST_ARG_STACK_OFFS);

                instruction storeIns = m_compiler->codeGen->ins_Store(use.GetType());
                if (!ppc64leOffsetFitsInstruction(storeIns, offset))
                {
                    needsOffsetTmp = true;
                }
            }

            if (needsOffsetTmp)
            {
                buildInternalIntRegisterDefForNode(argNode);
            }
        }
        else
        {
            buildInternalIntRegisterDefForNode(argNode);
            buildInternalIntRegisterDefForNode(argNode);

            assert(src->isContained());
            if (src->OperIs(GT_BLK))
            {
                srcCount = BuildOperandUses(src->AsBlk()->Addr());
            }
            else
            {
                assert(src->OperIs(GT_LCL_VAR, GT_LCL_FLD));
            }
        }
    }
    else
    {
        bool fpBased = false;
        int  offset = m_compiler->lvaFrameAddress(m_compiler->lvaOutgoingArgSpaceVar, &fpBased) +
                     static_cast<int>(argNode->getArgOffset() + FIRST_ARG_STACK_OFFS);
        instruction storeIns = m_compiler->codeGen->ins_Store(genActualType(src));
        emitAttr    storeAttr = emitTypeSize(genActualType(src));

        if ((EA_SIZE(storeAttr) < EA_PTRSIZE) && varTypeUsesIntReg(genActualType(src)))
        {
            storeIns = INS_std;
        }

        if (!ppc64leOffsetFitsInstruction(storeIns, offset))
        {
            buildInternalIntRegisterDefForNode(argNode);
        }

        assert(!src->isContained());
        srcCount = BuildOperandUses(src);
    }

    buildInternalRegisterUses();
    return srcCount;
}

//------------------------------------------------------------------------
// BuildBlockStore: Build the RefPositions for a block store node.
//
// Arguments:
//    blkNode - The block store node of interest
//
// Return Value:
//    The number of sources consumed by this node.
//
int LinearScan::BuildBlockStore(GenTreeBlk* blkNode)
{
    GenTree* dstAddr = blkNode->Addr();
    GenTree* src     = blkNode->Data();
    unsigned size    = blkNode->Size();

    GenTree* srcAddrOrFill = nullptr;

    SingleTypeRegSet dstAddrRegMask = RBM_NONE;
    SingleTypeRegSet srcRegMask     = RBM_NONE;

    if (blkNode->OperIsInitBlkOp())
    {
        if (src->OperIs(GT_INIT_VAL))
        {
            assert(src->isContained());
            src = src->AsUnOp()->gtGetOp1();
        }

        srcAddrOrFill = src;

        switch (blkNode->gtBlkOpKind)
        {
            case GenTreeBlk::BlkOpKindUnroll:
                if (dstAddr->isContained())
                {
                    buildInternalIntRegisterDefForNode(blkNode);
                }
                break;

            case GenTreeBlk::BlkOpKindLoop:
                buildInternalIntRegisterDefForNode(blkNode, availableIntRegs);
                break;

            default:
                unreached();
        }
    }
    else
    {
        if (src->OperIs(GT_IND))
        {
            assert(src->isContained());
            srcAddrOrFill = src->AsIndir()->Addr();
        }

        switch (blkNode->gtBlkOpKind)
        {
            case GenTreeBlk::BlkOpKindCpObjUnroll:
            {
                SingleTypeRegSet internalIntCandidates =
                    allRegs(TYP_INT) &
                    ~(RBM_WRITE_BARRIER_DST_BYREF | RBM_WRITE_BARRIER_SRC_BYREF).GetRegSetForType(IntRegisterType);
                buildInternalIntRegisterDefForNode(blkNode, internalIntCandidates);

                if (size >= 2 * REGSIZE_BYTES)
                {
                    buildInternalIntRegisterDefForNode(blkNode, internalIntCandidates);
                }

                dstAddrRegMask = RBM_WRITE_BARRIER_DST_BYREF.GetIntRegSet();

                if (srcAddrOrFill != nullptr)
                {
                    assert(!srcAddrOrFill->isContained());
                    srcRegMask = RBM_WRITE_BARRIER_SRC_BYREF.GetIntRegSet();
                }
                break;
            }

            case GenTreeBlk::BlkOpKindUnroll:
                buildInternalIntRegisterDefForNode(blkNode);
                if (size >= 2 * REGSIZE_BYTES)
                {
                    buildInternalIntRegisterDefForNode(blkNode);
                }
                if (ppc64leContainedAddrNeedsLargeOffsetTemp(m_compiler, dstAddr, size))
                {
                    buildInternalIntRegisterDefForNode(blkNode);
                }
                break;

            default:
                unreached();
        }
    }

    int useCount = 0;

    if (!dstAddr->isContained())
    {
        useCount++;
        BuildUse(dstAddr, dstAddrRegMask);
    }
    else if (dstAddr->OperIsAddrMode())
    {
        useCount += BuildAddrUses(dstAddr->AsAddrMode()->Base());
    }

    if (srcAddrOrFill != nullptr)
    {
        if (!srcAddrOrFill->isContained())
        {
            useCount++;
            BuildUse(srcAddrOrFill, srcRegMask);
        }
        else if (srcAddrOrFill->OperIsAddrMode())
        {
            useCount += BuildAddrUses(srcAddrOrFill->AsAddrMode()->Base());
        }
    }

    buildInternalRegisterUses();
    regMaskTP killMask = getKillSetForBlockStore(blkNode);
    BuildKills(blkNode, killMask);
    return useCount;
}

#endif // TARGET_POWERPC64
