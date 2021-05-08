// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

import CryptoKit
import Foundation

@_cdecl("AppleCryptoNative_AesGcmEncrypt")
public func AppleCryptoNative_AesGcmEncrypt(
    keyPtr: UnsafeMutableRawPointer,
    keyLength: Int32,
    noncePtr: UnsafeMutableRawPointer,
    nonceLength: Int32,
    plaintextPtr: UnsafeMutableRawPointer,
    plaintextLength: Int32,
    ciphertextBuffer: UnsafeMutablePointer<UInt8>,
    ciphertextBufferLength: Int32,
    tagBuffer: UnsafeMutablePointer<UInt8>,
    tagBufferLength: Int32,
    aadPtr: UnsafeMutableRawPointer,
    aadLength: Int32
) -> Int32 {
    if #available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *) {
        let nonceData = Data(bytesNoCopy: noncePtr, count: Int(nonceLength), deallocator: Data.Deallocator.none)
        let key = Data(bytesNoCopy: keyPtr, count: Int(keyLength), deallocator: Data.Deallocator.none)
        let plaintext = Data(bytesNoCopy: plaintextPtr, count: Int(plaintextLength), deallocator: Data.Deallocator.none)
        let aad = Data(bytesNoCopy: aadPtr, count: Int(aadLength), deallocator: Data.Deallocator.none)
        let symmetricKey = SymmetricKey(data: key)
        guard let nonce = try? AES.GCM.Nonce(data: nonceData) else {
            return 0
        }
        guard let result = try? AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce, authenticating: aad) else {
            return 0
        }
        assert(ciphertextBufferLength >= result.ciphertext.count)
        //assert(tagBufferLength >= result.tag.count)

        result.ciphertext.copyBytes(to: ciphertextBuffer, count: result.ciphertext.count)
        result.tag.copyBytes(to: tagBuffer, count: min(result.tag.count, Int(tagBufferLength)))
        return 1
    }
    return -1
}

@_cdecl("AppleCryptoNative_AesGcmDecrypt")
public func AppleCryptoNative_AesGcmDecrypt(
    keyPtr: UnsafeMutableRawPointer,
    keyLength: Int32,
    noncePtr: UnsafeMutableRawPointer,
    nonceLength: Int32,
    ciphertextPtr: UnsafeMutableRawPointer,
    ciphertextLength: Int32,
    tagPtr: UnsafeMutableRawPointer,
    tagLength: Int32,
    plaintextBuffer: UnsafeMutablePointer<UInt8>,
    plaintextBufferLength: Int32,
    aadPtr: UnsafeMutableRawPointer,
    aadLength: Int32
) -> Int32 {
    if #available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *) {
        let nonceData = Data(bytesNoCopy: noncePtr, count: Int(nonceLength), deallocator: Data.Deallocator.none)
        let key = Data(bytesNoCopy: keyPtr, count: Int(keyLength), deallocator: Data.Deallocator.none)
        let ciphertext = Data(bytesNoCopy: ciphertextPtr, count: Int(ciphertextLength), deallocator: Data.Deallocator.none)
        let aad = Data(bytesNoCopy: aadPtr, count: Int(aadLength), deallocator: Data.Deallocator.none)
        let tag = Data(bytesNoCopy: tagPtr, count: Int(tagLength), deallocator: Data.Deallocator.none)
        let symmetricKey = SymmetricKey(data: key)
        guard let nonce = try? AES.GCM.Nonce(data: nonceData) else {
            return 0
        }
        guard let sealedBoxRestored = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag) else {
            return 0
        }
        guard let result = try? AES.GCM.open(sealedBoxRestored, using: symmetricKey, authenticating: aad) else {
            return 0
        }
        assert(plaintextBufferLength >= result.count)

        result.copyBytes(to: plaintextBuffer, count: result.count)
        return 1
    }
    return -1
}

@_cdecl("AppleCryptoNative_ChaChaPolyEncrypt")
public func AppleCryptoNative_ChaChaPolyEncrypt(
    keyPtr: UnsafeMutableRawPointer,
    keyLength: Int32,
    noncePtr: UnsafeMutableRawPointer,
    nonceLength: Int32,
    plaintextPtr: UnsafeMutableRawPointer,
    plaintextLength: Int32,
    ciphertextBuffer: UnsafeMutablePointer<UInt8>,
    ciphertextBufferLength: Int32,
    tagBuffer: UnsafeMutablePointer<UInt8>,
    tagBufferLength: Int32,
    aadPtr: UnsafeMutableRawPointer,
    aadLength: Int32
) -> Int32 {
    if #available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *) {
        let nonceData = Data(bytesNoCopy: noncePtr, count: Int(nonceLength), deallocator: Data.Deallocator.none)
        let key = Data(bytesNoCopy: keyPtr, count: Int(keyLength), deallocator: Data.Deallocator.none)
        let plaintext = Data(bytesNoCopy: plaintextPtr, count: Int(plaintextLength), deallocator: Data.Deallocator.none)
        let aad = Data(bytesNoCopy: aadPtr, count: Int(aadLength), deallocator: Data.Deallocator.none)
        let symmetricKey = SymmetricKey(data: key)
        guard let nonce = try? ChaChaPoly.Nonce(data: nonceData) else {
            return 0
        }
        guard let result = try? ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: nonce, authenticating: aad) else {
            return 0
        }
        assert(ciphertextBufferLength >= result.ciphertext.count)
        assert(tagBufferLength >= result.tag.count)

        result.ciphertext.copyBytes(to: ciphertextBuffer, count: result.ciphertext.count)
        result.tag.copyBytes(to: tagBuffer, count: result.tag.count)
        return 1
    }
    return -1
}

@_cdecl("AppleCryptoNative_ChaChaPolyDecrypt")
public func AppleCryptoNative_ChaChaPolyDecrypt(
    keyPtr: UnsafeMutableRawPointer,
    keyLength: Int32,
    noncePtr: UnsafeMutableRawPointer,
    nonceLength: Int32,
    ciphertextPtr: UnsafeMutableRawPointer,
    ciphertextLength: Int32,
    tagPtr: UnsafeMutableRawPointer,
    tagLength: Int32,
    plaintextBuffer: UnsafeMutablePointer<UInt8>,
    plaintextBufferLength: Int32,
    aadPtr: UnsafeMutableRawPointer,
    aadLength: Int32
) -> Int32 {
    if #available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *) {
        let nonceData = Data(bytesNoCopy: noncePtr, count: Int(nonceLength), deallocator: Data.Deallocator.none)
        let key = Data(bytesNoCopy: keyPtr, count: Int(keyLength), deallocator: Data.Deallocator.none)
        let ciphertext = Data(bytesNoCopy: ciphertextPtr, count: Int(ciphertextLength), deallocator: Data.Deallocator.none)
        let aad = Data(bytesNoCopy: aadPtr, count: Int(aadLength), deallocator: Data.Deallocator.none)
        let tag = Data(bytesNoCopy: tagPtr, count: Int(tagLength), deallocator: Data.Deallocator.none)
        let symmetricKey = SymmetricKey(data: key)
        guard let nonce = try? ChaChaPoly.Nonce(data: nonceData) else {
            return 0
        }
        guard let sealedBoxRestored = try? ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag) else {
            return 0
        }
        guard let result = try? ChaChaPoly.open(sealedBoxRestored, using: symmetricKey, authenticating: aad) else {
            return 0
        }
        assert(plaintextBufferLength >= result.count)

        result.copyBytes(to: plaintextBuffer, count: result.count)
        return 1
    }
    return -1
}
