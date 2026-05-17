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
}

void Lowering::ContainCheckIndir(GenTreeIndir* node)
{
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
    return false;
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
    return node;
}

GenTree* Lowering::LowerMul(GenTreeOp* mul)
{
    ContainCheckMul(mul);
    return mul;
}

GenTree* Lowering::LowerBinaryArithmetic(GenTreeOp* binOp)
{
    ContainCheckBinary(binOp);
    return binOp;
}

void Lowering::LowerBlockStore(GenTreeBlk* blkNode)
{
}

void Lowering::LowerPutArgStk(GenTreePutArgStk* putArgNode)
{
}

void Lowering::LowerCast(GenTree* node)
{
    ContainCheckCast(node->AsCast());
}

GenTree* Lowering::LowerStoreLoc(GenTreeLclVarCommon* tree)
{
    ContainCheckStoreLoc(tree);
    return tree;
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
}

void Lowering::ContainCheckStoreLoc(GenTreeLclVarCommon* storeLoc) const
{
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
