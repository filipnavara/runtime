// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        private static int AppleCryptoNative_DsaGenerateSignature(
            SafeSecKeyRefHandle privateKey,
            ReadOnlySpan<byte> pbDataHash,
            out SafeCFDataHandle pSignatureOut,
            out SafeCFErrorHandle pErrorOut) =>
            AppleCryptoNative_DsaGenerateSignature(
                privateKey,
                ref MemoryMarshal.GetReference(pbDataHash),
                pbDataHash.Length,
                out pSignatureOut,
                out pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_DsaGenerateSignature(
            SafeSecKeyRefHandle privateKey,
            ref byte pbDataHash,
            int cbDataHash,
            out SafeCFDataHandle pSignatureOut,
            out SafeCFErrorHandle pErrorOut);

        private static int AppleCryptoNative_DsaVerifySignature(
            SafeSecKeyRefHandle publicKey,
            ReadOnlySpan<byte> pbDataHash,
            ReadOnlySpan<byte> pbSignature,
            out SafeCFErrorHandle pErrorOut) =>
            AppleCryptoNative_DsaVerifySignature(
                publicKey,
                ref MemoryMarshal.GetReference(pbDataHash),
                pbDataHash.Length,
                ref MemoryMarshal.GetReference(pbSignature),
                pbSignature.Length,
                out pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_DsaVerifySignature(
            SafeSecKeyRefHandle publicKey,
            ref byte pbDataHash,
            int cbDataHash,
            ref byte pbSignature,
            int cbSignature,
            out SafeCFErrorHandle pErrorOut);

        internal static byte[] DsaGenerateSignature(SafeSecKeyRefHandle privateKey, ReadOnlySpan<byte> dataHash)
        {
            Debug.Assert(privateKey != null, "privateKey != null");

            int result = AppleCryptoNative_DsaGenerateSignature(
                privateKey,
                dataHash,
                out SafeCFDataHandle signature,
                out SafeCFErrorHandle error);

            using (error)
            using (signature)
            {
                return result switch
                {
                    kSuccess => CoreFoundation.CFGetData(signature),
                    kErrorSeeError => throw CreateExceptionForCFError(error),
                    _ => throw new CryptographicException { HResult = result }
                };
            }
        }

        internal static bool DsaVerifySignature(
            SafeSecKeyRefHandle publicKey,
            ReadOnlySpan<byte> dataHash,
            ReadOnlySpan<byte> signature)
        {
            const int Valid = 1;
            const int Invalid = 0;

            Debug.Assert(publicKey != null, "publicKey != null");

            int result = AppleCryptoNative_DsaVerifySignature(
                publicKey,
                dataHash,
                signature,
                out SafeCFErrorHandle error);

            using (error)
            {
                return result switch
                {
                    Valid => true,
                    Invalid => false,
                    kErrorSeeError => throw CreateExceptionForCFError(error),
                    _ => throw new CryptographicException { HResult = result }
                };
            }
        }
    }
}
