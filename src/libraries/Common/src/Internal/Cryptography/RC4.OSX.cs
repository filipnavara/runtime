// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static partial class RC4
    {
        private static ICryptoTransform CreateTransformCore(
            byte[] key,
            bool encrypting)
        {
            BasicSymmetricCipher cipher = new AppleCCCryptor(
                Interop.AppleCrypto.PAL_SymmetricAlgorithm.RC4,
                CipherMode.ECB, // unused
                1,
                key,
                null,
                encrypting,
                0, // unused, stream cipher with no feedback or padding
                0);

            return UniversalCryptoTransform.Create(PaddingMode.None, cipher, encrypting);
        }
    }
}
