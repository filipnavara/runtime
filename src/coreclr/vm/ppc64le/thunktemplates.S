// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "AsmMacros_Shared.h"

.abiversion 2
.text

#ifdef FEATURE_TIERED_COMPILATION
LEAF_ENTRY CallCountingStubCode
    mflr 0
    bl LOCAL_LABEL(GetPc)
LOCAL_LABEL(GetPc):
    mflr 11
    mtlr 0
    addi 11, 11, 0x3ff8

    // CallCountingStubData: RemainingCallCountCell, TargetForMethod, TargetForThresholdReached.
    // Keep the threshold token in r11; r12 carries the branch target at the next entry.
    mtctr 11
    ld 11, 0(11)
    lhz 0, 0(11)
    addic. 0, 0, -1
    sth 0, 0(11)
    beq LOCAL_LABEL(CountReachedZero)

    mfctr 12
    ld 12, 8(12)
    mtctr 12
    bctr

LOCAL_LABEL(CountReachedZero):
    mfctr 12
    ld 12, 16(12)
    mtctr 12
    bctr
LEAF_END_MARKED CallCountingStubCode, _TEXT
#endif
