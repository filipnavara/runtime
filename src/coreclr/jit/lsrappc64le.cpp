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

        case GT_STORE_LCL_VAR:
        case GT_STORE_LCL_FLD:
            return BuildStoreLoc(tree->AsLclVarCommon());

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

#endif // TARGET_POWERPC64
