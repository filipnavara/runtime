// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Cryptography;
using System.Diagnostics;
using Internal.NativeCrypto;

namespace Internal.Cryptography
{
    internal static partial class RC4
    {
        private static ICryptoTransform CreateTransformCore(
            byte[] key,
            int effectiveKeyLength,
            byte[]? iv,
            int blockSize,
            bool encrypting)
        {
            using (SafeAlgorithmHandle algorithm = Cng.BCryptOpenAlgorithmProvider(Cng.BCRYPT_RC4_ALGORITHM, null, Cng.OpenAlgorithmProviderFlags.NONE))
            {
                // The BasicSymmetricCipherBCrypt ctor will increase algorithm reference count and take ownership.
                BasicSymmetricCipher cipher = new BasicSymmetricCipherBCrypt(algorithm, CipherMode.ECB, 1, 0, key, true, null, encrypting);
                return UniversalCryptoTransform.Create(PaddingMode.None, cipher, encrypting);
            }
        }
    }
}
