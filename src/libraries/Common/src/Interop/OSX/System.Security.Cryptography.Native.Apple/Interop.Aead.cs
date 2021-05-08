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
        internal static unsafe void AesGcmEncrypt(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag,
            ReadOnlySpan<byte> aad)
        {
            fixed (byte* keyPtr = key)
            fixed (byte* noncePtr = nonce)
            fixed (byte* plaintextPtr = plaintext)
            fixed (byte* ciphertextPtr = ciphertext)
            fixed (byte* tagPtr = tag)
            fixed (byte* aadPtr = aad)
            {
                int result = AppleCryptoNative_AesGcmEncrypt(
                    keyPtr, key.Length,
                    noncePtr, nonce.Length,
                    plaintextPtr, plaintext.Length,
                    ciphertextPtr, ciphertext.Length,
                    tagPtr, tag.Length,
                    aadPtr, aad.Length);
                if (result != 1)
                {
                    CryptographicOperations.ZeroMemory(ciphertext);
                    CryptographicOperations.ZeroMemory(tag);
                    throw new CryptographicException();
                }
            }
        }

        internal static unsafe void AesGcmDecrypt(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> aad)
        {
            fixed (byte* keyPtr = key)
            fixed (byte* noncePtr = nonce)
            fixed (byte* ciphertextPtr = ciphertext)
            fixed (byte* tagPtr = tag)
            fixed (byte* plaintextPtr = plaintext)
            fixed (byte* aadPtr = aad)
            {
                int result = AppleCryptoNative_AesGcmDecrypt(
                    keyPtr, key.Length,
                    noncePtr, nonce.Length,
                    ciphertextPtr, ciphertext.Length,
                    tagPtr, tag.Length,
                    plaintextPtr, plaintext.Length,
                    aadPtr, aad.Length);
                if (result != 1)
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                    throw new CryptographicException();
                }
            }
        }

        internal static unsafe void ChaChaPolyEncrypt(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag,
            ReadOnlySpan<byte> aad)
        {
            fixed (byte* keyPtr = key)
            fixed (byte* noncePtr = nonce)
            fixed (byte* plaintextPtr = plaintext)
            fixed (byte* ciphertextPtr = ciphertext)
            fixed (byte* tagPtr = tag)
            fixed (byte* aadPtr = aad)
            {
                int result = AppleCryptoNative_ChaChaPolyEncrypt(
                    keyPtr, key.Length,
                    noncePtr, nonce.Length,
                    plaintextPtr, plaintext.Length,
                    ciphertextPtr, ciphertext.Length,
                    tagPtr, tag.Length,
                    aadPtr, aad.Length);
                if (result != 1)
                {
                    CryptographicOperations.ZeroMemory(ciphertext);
                    CryptographicOperations.ZeroMemory(tag);
                    throw new CryptographicException();
                }
            }
        }

        internal static unsafe void ChaChaPolyDecrypt(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> aad)
        {
            fixed (byte* keyPtr = key)
            fixed (byte* noncePtr = nonce)
            fixed (byte* ciphertextPtr = ciphertext)
            fixed (byte* tagPtr = tag)
            fixed (byte* plaintextPtr = plaintext)
            fixed (byte* aadPtr = aad)
            {
                int result = AppleCryptoNative_ChaChaPolyDecrypt(
                    keyPtr, key.Length,
                    noncePtr, nonce.Length,
                    ciphertextPtr, ciphertext.Length,
                    tagPtr, tag.Length,
                    plaintextPtr, plaintext.Length,
                    aadPtr, aad.Length);
                if (result != 1)
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                    throw new CryptographicException();
                }
            }
        }

        [DllImport(Libraries.AppleCryptoNative)]
        private static unsafe extern int AppleCryptoNative_AesGcmEncrypt(
            byte* keyPtr,
            int keyLength,
            byte* noncePtr,
            int nonceLength,
            byte* plaintextPtr,
            int plaintextLength,
            byte* ciphertextPtr,
            int ciphertextLength,
            byte* tagPtr,
            int tagLength,
            byte* aadPtr,
            int aadLength);

        [DllImport(Libraries.AppleCryptoNative)]
        private static unsafe extern int AppleCryptoNative_AesGcmDecrypt(
            byte* keyPtr,
            int keyLength,
            byte* noncePtr,
            int nonceLength,
            byte* ciphertextPtr,
            int ciphertextLength,
            byte* tagPtr,
            int tagLength,
            byte* plaintextPtr,
            int plaintextLength,
            byte* aadPtr,
            int aadLength);

        [DllImport(Libraries.AppleCryptoNative)]
        private static unsafe extern int AppleCryptoNative_ChaChaPolyEncrypt(
            byte* keyPtr,
            int keyLength,
            byte* noncePtr,
            int nonceLength,
            byte* plaintextPtr,
            int plaintextLength,
            byte* ciphertextPtr,
            int ciphertextLength,
            byte* tagPtr,
            int tagLength,
            byte* aadPtr,
            int aadLength);

        [DllImport(Libraries.AppleCryptoNative)]
        private static unsafe extern int AppleCryptoNative_ChaChaPolyDecrypt(
            byte* keyPtr,
            int keyLength,
            byte* noncePtr,
            int nonceLength,
            byte* ciphertextPtr,
            int ciphertextLength,
            byte* tagPtr,
            int tagLength,
            byte* plaintextPtr,
            int plaintextLength,
            byte* aadPtr,
            int aadLength);
    }
}
