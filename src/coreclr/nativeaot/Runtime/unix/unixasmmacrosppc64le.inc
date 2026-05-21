// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include <ppc64le/InlineTls.inc>

// Inlined version of RhpGetThread.
.macro INLINE_GETTHREAD target
    INLINE_GET_TLS_VAR \target, C_FUNC(tls_CurrentThread)
.endm

.macro INLINE_GET_ALLOC_CONTEXT_BASE target
    INLINE_GETTHREAD \target
.endm
