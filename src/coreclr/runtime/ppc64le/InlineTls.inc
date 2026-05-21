// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// Loads the address of a thread-local variable into the target register.
.macro INLINE_GET_TLS_VAR target, var
    addis \target, 2, \var@got@tprel@ha
    ld \target, \var@got@tprel@l(\target)
    add \target, \target, \var@tls
.endm
