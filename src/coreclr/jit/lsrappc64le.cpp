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

static bool ppc64leNeedsLargeLclOffsetTemp(Compiler* compiler, GenTreeLclVarCommon* lclNode)
{
    bool fpBased = false;
    int  offset  = compiler->lvaFrameAddress(lclNode->GetLclNum(), &fpBased) + lclNode->GetLclOffs();
    return !emitter::isValidSimm16(offset);
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

    return !ppc64leOffsetRangeFitsSimm16(offset, size);
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
            if (!varDsc->lvIsRegCandidate() && !tree->AsLclVar()->IsMultiReg() &&
                ((tree->gtFlags & GTF_SPILLED) == 0) && ppc64leNeedsLargeLclOffsetTemp(m_compiler, tree->AsLclVar()))
            {
                buildInternalIntRegisterDefForNode(tree);
                buildInternalRegisterUses();
            }

            BuildDef(tree);
            return 0;
        }

        case GT_LCL_FLD:
            if (!tree->TypeIs(TYP_STRUCT) && ppc64leNeedsLargeLclOffsetTemp(m_compiler, tree->AsLclFld()))
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
            buildInternalIntRegisterDefForNode(tree);
            buildInternalRegisterUses();
            BuildDef(tree);
            return srcCount;
        }

        case GT_BSWAP:
        case GT_BSWAP16:
        {
            int srcCount = BuildOperandUses(tree->gtGetOp1());
            buildInternalIntRegisterDefForNode(tree);
            buildInternalRegisterUses();
            BuildDef(tree);
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

        case GT_RETURNTRAP:
        {
            BuildUse(tree->gtGetOp1());
            regMaskTP killMask = m_compiler->compHelperCallKillSet(CORINFO_HELP_STOP_FOR_GC);
            BuildKills(tree, killMask);
            return 1;
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

    if (!emitter::isValidSimm16(indirTree->Offset()))
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

        if (ctrlExpr->isContainedIntOrIImmed())
        {
            buildInternalIntRegisterDefForNode(call);
        }
    }
    else if (call->IsR2ROrVirtualStubRelativeIndir())
    {
        SingleTypeRegSet candidates = RBM_NONE;
        if (call->IsFastTailCall())
        {
            candidates = allRegs(TYP_INT) & RBM_INT_CALLEE_TRASH.GetIntRegSet();
            assert(candidates != RBM_NONE);
        }

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
            for (GenTreeFieldList::Use& use : src->AsFieldList()->Uses())
            {
                BuildUse(use.GetNode());
                srcCount++;
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
                     static_cast<int>(argNode->getArgOffset()) + FIRST_ARG_STACK_OFFS;
        if (!emitter::isValidSimm16(offset))
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
