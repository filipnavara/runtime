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
#include "lsra.h"

int LinearScan::BuildNode(GenTree* tree)
{
    assert(!tree->isContained());
    clearBuildState();

    switch (tree->OperGet())
    {
        case GT_LCL_VAR:
            if (checkContainedOrCandidateLclVar(tree->AsLclVar()))
            {
                return 0;
            }
            FALLTHROUGH;

        case GT_LCL_FLD:
            BuildDef(tree);
            return 0;

        case GT_LCL_ADDR:
            BuildDef(tree);
            return 0;

        case GT_STORE_LCL_VAR:
        case GT_STORE_LCL_FLD:
            return BuildStoreLoc(tree->AsLclVarCommon());

        case GT_STOREIND:
        {
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

        case GT_CAST:
        {
            int srcCount = BuildCastUses(tree->AsCast(), RBM_NONE);
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

        default:
            return BuildSimple(tree);
    }
}

int LinearScan::BuildIndir(GenTreeIndir* indirTree)
{
    assert(!indirTree->TypeIs(TYP_STRUCT));

    int srcCount = BuildIndirUses(indirTree);

    if (!indirTree->OperIs(GT_STOREIND, GT_NULLCHECK))
    {
        BuildDef(indirTree);
    }

    return srcCount;
}

#endif // TARGET_POWERPC64
