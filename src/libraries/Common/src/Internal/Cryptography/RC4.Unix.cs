// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static partial class RC4
    {
        private static ICryptoTransform CreateTransformCore(
            byte[] key,
            bool encrypting)
        {
            Interop.Crypto.EnsureLegacyAlgorithmsRegistered();

            // The algorithm pointer is a static pointer, so not having any cleanup code is correct.
            BasicSymmetricCipher cipher = new OpenSslCipher(Interop.Crypto.EvpRC4(), CipherMode.ECB, 1, 0, key, key.Length * 8, null, encrypting);
            return UniversalCryptoTransform.Create(PaddingMode.None, cipher, encrypting);
        }
    }
}
