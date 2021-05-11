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
        private static bool UseCryptoKit => false;

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
                if (UseCryptoKit)
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
                else
                {
                    int result = CCCryptorGCMOneshotEncrypt(
                        0,
                        keyPtr, key.Length,
                        noncePtr, nonce.Length,
                        aadPtr, aad.Length,
                        plaintextPtr == null ? (byte*)0x42 : plaintextPtr, plaintext.Length,
                        ciphertextPtr == null ? (byte*)0x42 : ciphertextPtr,
                        tagPtr, tag.Length);

                    if (result != 0)
                    {
                        CryptographicOperations.ZeroMemory(ciphertext);
                        CryptographicOperations.ZeroMemory(tag);
                        throw new CryptographicException();
                    }
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
                if (UseCryptoKit)
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
                else
                {
                    int result = CCCryptorGCMOneshotDecrypt(
                        0,
                        keyPtr, key.Length,
                        noncePtr, nonce.Length,
                        aadPtr, aad.Length,
                        ciphertextPtr == null ? (byte*)0x42 : ciphertextPtr, ciphertext.Length,
                        plaintextPtr == null ? (byte*)0x42 : plaintextPtr,
                        tagPtr, tag.Length);

                    if (result != 0)
                    {
                        CryptographicOperations.ZeroMemory(plaintext);
                        throw new CryptographicException();
                    }
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
                if (UseCryptoKit)
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
                else
                {
                    int result = CCCryptorChaCha20Poly1305OneshotEncrypt(
                        keyPtr, key.Length,
                        noncePtr, nonce.Length,
                        aadPtr, aad.Length,
                        plaintextPtr == null ? (byte*)0x42 : plaintextPtr, plaintext.Length,
                        ciphertextPtr == null ? (byte*)0x42 : ciphertextPtr,
                        tagPtr, tag.Length);

                    if (result != 0)
                    {
                        CryptographicOperations.ZeroMemory(ciphertext);
                        CryptographicOperations.ZeroMemory(tag);
                        throw new CryptographicException();
                    }
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
                if (UseCryptoKit)
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
                else
                {
                    int result = CCCryptorChaCha20Poly1305OneshotDecrypt(
                        keyPtr, key.Length,
                        noncePtr, nonce.Length,
                        aadPtr, aad.Length,
                        ciphertextPtr == null ? (byte*)0x42 : ciphertextPtr, ciphertext.Length,
                        plaintextPtr == null ? (byte*)0x42 : plaintextPtr,
                        tagPtr, tag.Length);

                    if (result != 0)
                    {
                        CryptographicOperations.ZeroMemory(plaintext);
                        throw new CryptographicException();
                    }
                }
            }
        }

        [DllImport("/usr/lib/system/libcommonCrypto.dylib")]
        private static unsafe extern int CCCryptorGCMOneshotEncrypt(
            int algorithm,
            byte *keyPtr,
            nint keyLength,
            byte *noncePtr,
            nint nonceLength,
            byte *aadPtr,
            nint aadLength,
            byte *plaintextPtr,
            nint plaintextLength,
            byte *ciphertextPtr,
            byte *tagPtr,
            nint tagLength);

        [DllImport("/usr/lib/system/libcommonCrypto.dylib")]
        private static unsafe extern int CCCryptorGCMOneshotDecrypt(
            int algorithm,
            byte *keyPtr,
            nint keyLength,
            byte *noncePtr,
            nint nonceLength,
            byte *aadPtr,
            nint aadLength,
            byte *ciphertextPtr,
            nint ciphertextLength,
            byte *plaintextPtr,
            byte *tagPtr,
            nint tagLength);

        [DllImport("/usr/lib/system/libcommonCrypto.dylib")]
        private static unsafe extern int CCCryptorChaCha20Poly1305OneshotEncrypt(
            byte *keyPtr,
            nint keyLength,
            byte *noncePtr,
            nint nonceLength,
            byte *aadPtr,
            nint aadLength,
            byte *plaintextPtr,
            nint plaintextLength,
            byte *ciphertextPtr,
            byte *tagPtr,
            nint tagLength);

        [DllImport("/usr/lib/system/libcommonCrypto.dylib")]
        private static unsafe extern int CCCryptorChaCha20Poly1305OneshotDecrypt(
            byte *keyPtr,
            nint keyLength,
            byte *noncePtr,
            nint nonceLength,
            byte *aadPtr,
            nint aadLength,
            byte *ciphertextPtr,
            nint ciphertextLength,
            byte *plaintextPtr,
            byte *tagPtr,
            nint tagLength);

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
