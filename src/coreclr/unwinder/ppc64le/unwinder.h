// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef __unwinder_ppc64le__
#define __unwinder_ppc64le__

#include "baseunwinder.h"

class OOPStackUnwinderPPC64LE : public OOPStackUnwinder
{
public:
    BOOL Unwind(T_CONTEXT* pContext);
};

#endif // __unwinder_ppc64le__
