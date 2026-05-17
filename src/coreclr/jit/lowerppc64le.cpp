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
