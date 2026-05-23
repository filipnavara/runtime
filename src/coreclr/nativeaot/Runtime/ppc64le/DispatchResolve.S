// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "AsmMacros_Shared.h"

.abiversion 2
.text

// Dispatching version of RhpResolveInterfaceMethod.
LEAF_ENTRY RhpInterfaceDispatch, _TEXT
    // Load the MethodTable from the object instance in r3. This triggers an AV
    // if we are dispatching on a null instance; the exception handling code
    // treats this as the dispatch helper AV location.
    ld 0, 0(3)

    // r11 contains the interface dispatch cell. RhpUniversalTransitionTailCall
    // expects r11 to contain the resolver target and r12 to contain its argument.
    mr 12, 11
    addis 11, 2, RhpCidResolve@toc@ha
    addi 11, 11, RhpCidResolve@toc@l
    b RhpUniversalTransitionTailCall
LEAF_END RhpInterfaceDispatch, _TEXT
