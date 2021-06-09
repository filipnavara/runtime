// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Security.Cryptography;
using System.Diagnostics;

namespace Internal.Cryptography
{
    internal static partial class RC4
    {
        public static ICryptoTransform CreateDecryptor(byte[] rgbKey)
        {
            if (rgbKey == null)
                throw new ArgumentNullException(nameof(rgbKey));

            return CreateTransformCore(rgbKey, encrypting: false);
        }

        public static ICryptoTransform CreateEncryptor(byte[] rgbKey)
        {
            if (rgbKey == null)
                throw new ArgumentNullException(nameof(rgbKey));

            return CreateTransformCore(rgbKey, encrypting: true);
        }
    }
}
