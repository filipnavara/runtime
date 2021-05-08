// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.CodeAnalysis;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
    public partial class AesGcm
    {
        private byte[]? _key;

        /*public static bool IsSupported { get; } =
            OperatingSystem.IsMacOSVersionAtLeast(10, 15) ||
            OperatingSystem.IsIOSVersionAtLeast(13, 0) ||
            OperatingSystem.IsTvOSVersionAtLeast(13, 0) ||
            OperatingSystem.IsMacCatalyst();*/

        [MemberNotNull(nameof(_key))]
        private void ImportKey(ReadOnlySpan<byte> key)
        {
            // Allocate pinned array to avoid GC leaving unintentional copies of the key
            // in memory.
            _key = GC.AllocateArray<byte>(key.Length, pinned: true);
            key.CopyTo(_key);
        }

        private void EncryptCore(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag,
            ReadOnlySpan<byte> associatedData = default)
        {
            Interop.AppleCrypto.AesGcmEncrypt(
                _key,
                nonce,
                plaintext,
                ciphertext,
                tag,
                associatedData);
        }

        private void DecryptCore(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> associatedData = default)
        {
            Interop.AppleCrypto.AesGcmDecrypt(
                _key,
                nonce,
                ciphertext,
                tag,
                plaintext,
                associatedData);
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_key);
        }
    }
}
