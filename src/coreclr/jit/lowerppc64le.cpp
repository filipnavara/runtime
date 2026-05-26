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

void Lowering::ContainCheckStoreIndir(GenTreeStoreInd* node)
{
    GenTree* src = node->Data();
    if (!varTypeIsFloating(src->TypeGet()) && src->IsIntegralConst(0))
    {
        MakeSrcContained(node, src);
    }

    ContainCheckIndir(node);
}

void Lowering::ContainCheckIndir(GenTreeIndir* node)
{
    if (node->TypeIs(TYP_STRUCT))
    {
        return;
    }

    GenTree* addr = node->Addr();
    if (addr->OperIs(GT_LEA) && !addr->AsAddrMode()->HasIndex() && IsSafeToContainMem(node, addr))
    {
        MakeSrcContained(node, addr);
    }
    else if (addr->OperIs(GT_LCL_ADDR) && !node->OperIs(GT_NULLCHECK) &&
             IsContainableLclAddr(addr->AsLclFld(), node->Size()))
    {
        MakeSrcContained(node, addr);
    }
}

void Lowering::ContainCheckBoundsChk(GenTreeBoundsChk* node)
{
}

bool Lowering::IsCallTargetInRange(void* addr)
{
    return true;
}

bool Lowering::IsContainableImmed(GenTree* parentNode, GenTree* childNode) const
{
    if (!childNode->IsCnsIntOrI() || childNode->AsIntCon()->ImmedValNeedsReloc(m_compiler))
    {
        return false;
    }

    switch (parentNode->OperGet())
    {
        case GT_STOREIND:
        case GT_STORE_LCL_VAR:
        case GT_STORE_LCL_FLD:
            return childNode->IsIntegralConst(0);

        default:
            return false;
    }
}

GenTree* Lowering::LowerJTrue(GenTreeOp* jtrue)
{
    GenTree*     op = jtrue->gtGetOp1();
    GenCondition cond;
    GenTree*     cmpOp1;
    GenTree*     cmpOp2;

    if (op->OperIsCompare() && !varTypeIsFloating(op->gtGetOp1()))
    {
        cond   = GenCondition::FromIntegralRelop(op);
        cmpOp1 = op->gtGetOp1();
        cmpOp2 = op->gtGetOp2();

        BlockRange().Remove(op);
    }
    else
    {
        cond   = GenCondition(GenCondition::NE);
        cmpOp1 = op;
        cmpOp2 = m_compiler->gtNewZeroConNode(cmpOp1->TypeGet());

        BlockRange().InsertBefore(jtrue, cmpOp2);
    }

    jtrue->ChangeOper(GT_JCMP);
    jtrue->gtOp1                 = cmpOp1;
    jtrue->gtOp2                 = cmpOp2;
    jtrue->AsOpCC()->gtCondition = cond;

    cmpOp1->ClearContained();
    cmpOp2->ClearContained();

    return jtrue->gtNext;
}

GenTree* Lowering::LowerStoreIndir(GenTreeStoreInd* node)
{
    ContainCheckStoreIndir(node);
    return node->gtNext;
}

GenTree* Lowering::LowerMul(GenTreeOp* mul)
{
    ContainCheckMul(mul);
    return mul->gtNext;
}

GenTree* Lowering::LowerBinaryArithmetic(GenTreeOp* binOp)
{
    if (binOp->OperIs(GT_AND, GT_OR, GT_XOR))
    {
        bool isOp1Negated = binOp->gtGetOp1()->OperIs(GT_NOT);
        bool isOp2Negated = binOp->gtGetOp2()->OperIs(GT_NOT);

        if (isOp1Negated != isOp2Negated)
        {
            GenTree* notNode = isOp1Negated ? binOp->gtGetOp1() : binOp->gtGetOp2();
            GenTree* opNode  = isOp1Negated ? binOp->gtGetOp2() : binOp->gtGetOp1();

            binOp->gtOp1 = opNode;
            binOp->gtOp2 = notNode->AsUnOp()->gtGetOp1();
            binOp->gtOp2->ClearContained();

            switch (binOp->OperGet())
            {
                case GT_AND:
                    binOp->ChangeOper(GT_AND_NOT);
                    break;
                case GT_OR:
                    binOp->ChangeOper(GT_OR_NOT);
                    break;
                default:
                    assert(binOp->OperIs(GT_XOR));
                    binOp->ChangeOper(GT_XOR_NOT);
                    break;
            }

            BlockRange().Remove(notNode);
        }
    }

    ContainCheckBinary(binOp);
    return binOp->gtNext;
}

void Lowering::LowerBlockStore(GenTreeBlk* blkNode)
{
    GenTree* dstAddr = blkNode->Addr();
    GenTree* src     = blkNode->Data();
    unsigned size    = blkNode->Size();

    if (blkNode->OperIsInitBlkOp())
    {
        if (src->OperIs(GT_INIT_VAL))
        {
            src->SetContained();
            src = src->AsUnOp()->gtGetOp1();
        }

        if ((size <= m_compiler->getUnrollThreshold(Compiler::UnrollKind::Memset)) && src->OperIs(GT_CNS_INT))
        {
            blkNode->gtBlkOpKind = GenTreeBlk::BlkOpKindUnroll;

            ssize_t fill = src->AsIntCon()->IconValue() & 0xFF;
            if (fill == 0)
            {
                src->SetContained();
            }
            else if (size >= REGSIZE_BYTES)
            {
                fill *= 0x0101010101010101LL;
                src->gtType = TYP_LONG;
            }
            else
            {
                fill *= 0x01010101;
            }
            src->AsIntCon()->SetIconValue(fill);

            ContainBlockStoreAddress(blkNode, size, dstAddr, nullptr);
        }
        else if (blkNode->IsZeroingGcPointersOnHeap())
        {
            blkNode->gtBlkOpKind = GenTreeBlk::BlkOpKindLoop;
            src->SetContained();
        }
        else
        {
            LowerBlockStoreAsHelperCall(blkNode);
        }
        return;
    }

    assert(src->OperIs(GT_IND, GT_LCL_VAR, GT_LCL_FLD));
    src->SetContained();

    if (src->OperIs(GT_LCL_VAR))
    {
        const unsigned srcLclNum = src->AsLclVar()->GetLclNum();
        m_compiler->lvaSetVarDoNotEnregister(srcLclNum DEBUGARG(DoNotEnregisterReason::BlockOp));
    }

    ClassLayout* layout               = blkNode->GetLayout();
    bool         doCpObj              = layout->HasGCPtr();
    unsigned     copyBlockUnrollLimit = m_compiler->getUnrollThreshold(Compiler::UnrollKind::Memcpy);

    if (doCpObj)
    {
        if (TryLowerBlockStoreAsGcBulkCopyCall(blkNode))
        {
            return;
        }

        assert(dstAddr->TypeIs(TYP_BYREF, TYP_I_IMPL));
        blkNode->gtBlkOpKind = GenTreeBlk::BlkOpKindCpObjUnroll;
    }
    else if (blkNode->OperIs(GT_STORE_BLK) && (size <= copyBlockUnrollLimit))
    {
        blkNode->gtBlkOpKind = GenTreeBlk::BlkOpKindUnroll;

        if (src->OperIs(GT_IND))
        {
            ContainBlockStoreAddress(blkNode, size, src->AsIndir()->Addr(), src->AsIndir());
        }

        ContainBlockStoreAddress(blkNode, size, dstAddr, nullptr);
    }
    else
    {
        assert(blkNode->OperIs(GT_STORE_BLK));
        LowerBlockStoreAsHelperCall(blkNode);
    }
}

void Lowering::ContainBlockStoreAddress(GenTreeBlk* blkNode, unsigned size, GenTree* addr, GenTree* addrParent)
{
    assert(blkNode->OperIs(GT_STORE_BLK) && (blkNode->gtBlkOpKind == GenTreeBlk::BlkOpKindUnroll));
    assert(size < INT32_MAX);

    if (addr->OperIs(GT_LCL_ADDR) && IsContainableLclAddr(addr->AsLclFld(), size))
    {
        addr->SetContained();
        return;
    }

    if (!addr->OperIs(GT_ADD) || addr->gtOverflow() || !addr->AsOp()->gtGetOp2()->OperIs(GT_CNS_INT))
    {
        return;
    }

    GenTreeIntCon* offsetNode = addr->AsOp()->gtGetOp2()->AsIntCon();
    ssize_t        offset     = offsetNode->IconValue();

    if (!emitter::isValidSimm16(offset) || !emitter::isValidSimm16(offset + static_cast<int>(size)))
    {
        return;
    }

    if (!IsSafeToContainMem(blkNode, addrParent, addr))
    {
        return;
    }

    BlockRange().Remove(offsetNode);

    addr->ChangeOper(GT_LEA);
    addr->AsAddrMode()->SetIndex(nullptr);
    addr->AsAddrMode()->SetScale(0);
    addr->AsAddrMode()->SetOffset(static_cast<int>(offset));
    addr->SetContained();
}

void Lowering::LowerPutArgStk(GenTreePutArgStk* putArgNode)
{
    GenTree* src = putArgNode->Data();

    if (src->TypeIs(TYP_STRUCT))
    {
        MakeSrcContained(putArgNode, src);

        if (src->OperIs(GT_LCL_VAR))
        {
            m_compiler->lvaSetVarDoNotEnregister(src->AsLclVar()->GetLclNum()
                                                     DEBUGARG(DoNotEnregisterReason::IsStructArg));
        }
    }
}

void Lowering::LowerCast(GenTree* node)
{
    ContainCheckCast(node->AsCast());
}

GenTree* Lowering::LowerStoreLoc(GenTreeLclVarCommon* tree)
{
    if (tree->OperIs(GT_STORE_LCL_FLD))
    {
        // We should only encounter this for lclVars that are lvDoNotEnregister.
        verifyLclFldDoNotEnregister(tree->GetLclNum());
    }

    ContainCheckStoreLoc(tree);
    return tree->gtNext;
}

void Lowering::LowerRotate(GenTree* tree)
{
    ContainCheckShiftRotate(tree->AsOp());
}

void Lowering::ContainCheckDivOrMod(GenTreeOp* node)
{
}

void Lowering::ContainCheckSelect(GenTreeOp* select)
{
}

void Lowering::ContainCheckCallOperands(GenTreeCall* call)
{
}

void Lowering::ContainCheckNonLocalJmp(GenTreeUnOp* node)
{
}

void Lowering::ContainCheckMul(GenTreeOp* node)
{
    ContainCheckBinary(node);
}

void Lowering::ContainCheckShiftRotate(GenTreeOp* node)
{
    GenTree* shiftBy = node->gtOp2;
    assert(node->OperIsShiftOrRotate());

    if (shiftBy->IsCnsIntOrI())
    {
        MakeSrcContained(node, shiftBy);
    }
}

void Lowering::ContainCheckStoreLoc(GenTreeLclVarCommon* storeLoc) const
{
    assert(storeLoc->OperIsLocalStore());

    GenTree* op1 = storeLoc->gtGetOp1();
    if (IsContainableImmed(storeLoc, op1))
    {
        MakeSrcContained(storeLoc, op1);
    }
}

void Lowering::ContainCheckCast(GenTreeCast* node)
{
}

void Lowering::ContainCheckCompare(GenTreeOp* node)
{
}

void Lowering::ContainCheckBinary(GenTreeOp* node)
{
}

#endif // TARGET_POWERPC64
