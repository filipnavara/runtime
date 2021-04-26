// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        internal enum PAL_SignatureAlgorithm : uint
        {
            Unknown = 0,
            RsaPkcs1 = 1,
            EC = 2,
            DSA = 3
        }

        private static unsafe int AppleCryptoNative_SecKeyVerifySignature(
            SafeSecKeyRefHandle publicKey,
            ReadOnlySpan<byte> dataHash,
            ReadOnlySpan<byte> signature,
            PAL_HashAlgorithm hashAlgorithm,
            PAL_SignatureAlgorithm signatureAlgorithm,
            bool digest,
            out SafeCFErrorHandle pErrorOut)
        {
            fixed (byte* pDataHash = dataHash)
            fixed (byte* pSignature = signature)
            {
                return AppleCryptoNative_SecKeyVerifySignature(
                    publicKey,
                    pDataHash,
                    dataHash.Length,
                    pSignature,
                    signature.Length,
                    hashAlgorithm,
                    signatureAlgorithm,
                    digest ? 1 : 0,
                    out pErrorOut);
            }
        }

        [DllImport(Libraries.AppleCryptoNative)]
        private static unsafe extern int AppleCryptoNative_SecKeyVerifySignature(
            SafeSecKeyRefHandle publicKey,
            byte* pbDataHash,
            int cbDataHash,
            byte* pbSignature,
            int cbSignature,
            PAL_HashAlgorithm hashAlgorithm,
            PAL_SignatureAlgorithm signatureAlgorithm,
            int digest,
            out SafeCFErrorHandle pErrorOut);

        private static unsafe int AppleCryptoNative_SecKeyCreateSignature(
            SafeSecKeyRefHandle privateKey,
            ReadOnlySpan<byte> dataHash,
            PAL_HashAlgorithm hashAlgorithm,
            PAL_SignatureAlgorithm signatureAlgorithm,
            bool digest,
            out SafeCFDataHandle pSignatureOut,
            out SafeCFErrorHandle pErrorOut)
        {
            fixed (byte* pDataHash = dataHash)
            {
                return AppleCryptoNative_SecKeyCreateSignature(
                    privateKey,
                    pDataHash,
                    dataHash.Length,
                    hashAlgorithm,
                    signatureAlgorithm,
                    digest ? 1 : 0,
                    out pSignatureOut,
                    out pErrorOut);
            }
        }

        [DllImport(Libraries.AppleCryptoNative)]
        private static unsafe extern int AppleCryptoNative_SecKeyCreateSignature(
            SafeSecKeyRefHandle privateKey,
            byte* pbDataHash,
            int cbDataHash,
            PAL_HashAlgorithm hashAlgorithm,
            PAL_SignatureAlgorithm signatureAlgorithm,
            int digest,
            out SafeCFDataHandle pSignatureOut,
            out SafeCFErrorHandle pErrorOut);

        internal static bool VerifySignature(
            SafeSecKeyRefHandle publicKey,
            ReadOnlySpan<byte> dataHash,
            ReadOnlySpan<byte> signature,
            PAL_HashAlgorithm hashAlgorithm,
            PAL_SignatureAlgorithm signatureAlgorithm,
            bool digest)
        {
            const int Valid = 1;
            const int Invalid = 0;

            int result = AppleCryptoNative_SecKeyVerifySignature(
                publicKey,
                dataHash,
                signature,
                hashAlgorithm,
                signatureAlgorithm,
                digest,
                out SafeCFErrorHandle errorHandle);

            using (errorHandle)
            {
                return result switch
                {
                    Valid => true,
                    Invalid => false,
                    kErrorSeeError => throw CreateExceptionForCFError(errorHandle),
                    kPlatformNotSupported => throw new PlatformNotSupportedException(),
                    _ => throw new CryptographicException { HResult = result }
                };
            }
        }

        internal static byte[] CreateSignature(
            SafeSecKeyRefHandle privateKey,
            ReadOnlySpan<byte> dataHash,
            PAL_HashAlgorithm hashAlgorithm,
            PAL_SignatureAlgorithm signatureAlgorithm,
            bool digest)
        {
            int result = AppleCryptoNative_SecKeyCreateSignature(
                privateKey,
                dataHash,
                hashAlgorithm,
                signatureAlgorithm,
                digest,
                out SafeCFDataHandle signature,
                out SafeCFErrorHandle errorHandle);

            using (errorHandle)
            using (signature)
            {
                return result switch
                {
                    kSuccess => CoreFoundation.CFGetData(signature),
                    kErrorSeeError => throw CreateExceptionForCFError(errorHandle),
                    kPlatformNotSupported => throw new PlatformNotSupportedException(),
                    _ => throw new CryptographicException { HResult = result }
                };
            }
        }

        internal static bool TryCreateSignature(
            SafeSecKeyRefHandle privateKey,
            ReadOnlySpan<byte> dataHash,
            Span<byte> destination,
            PAL_HashAlgorithm hashAlgorithm,
            PAL_SignatureAlgorithm signatureAlgorithm,
            bool digest,
            out int bytesWritten)
        {
            int result = AppleCryptoNative_SecKeyCreateSignature(
                privateKey,
                dataHash,
                hashAlgorithm,
                signatureAlgorithm,
                digest,
                out SafeCFDataHandle signature,
                out SafeCFErrorHandle errorHandle);

            using (errorHandle)
            using (signature)
            {
                return result switch
                {
                    kSuccess => CoreFoundation.TryCFWriteData(signature, destination, out bytesWritten),
                    kErrorSeeError => throw CreateExceptionForCFError(errorHandle),
                    kPlatformNotSupported => throw new PlatformNotSupportedException(),
                    _ => throw new CryptographicException { HResult = result }
                };
            }
        }
    }
}
