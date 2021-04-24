// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma once

#include "pal_digest.h"
#include "pal_seckey.h"
#include "pal_compiler.h"

#include <Security/Security.h>

#if !defined(TARGET_MACCATALYST) && !defined(TARGET_IOS) && !defined(TARGET_TVOS)
/*
Generate a DSA signature.

Follows pal_seckey return conventions.
*/
PALEXPORT int32_t AppleCryptoNative_DsaGenerateSignature(
    SecKeyRef privateKey, uint8_t* pbDataHash, int32_t cbDataHash, CFDataRef* pSignatureOut, CFErrorRef* pErrorOut);

/*
Verify a DSA signature.

Returns 1 when the signature is correct, 0 when it is incorrect, and otherwise
follows pal_seckey return conventions.
*/
PALEXPORT int32_t AppleCryptoNative_DsaVerifySignature(SecKeyRef publicKey,
                                                       uint8_t* pbDataHash,
                                                       int32_t cbDataHash,
                                                       uint8_t* pbSignature,
                                                       int32_t cbSignature,
                                                       CFErrorRef* pErrorOut);
#endif
