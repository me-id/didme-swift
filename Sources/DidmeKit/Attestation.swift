//
//  Attestation.swift
//  DidmeKit
//
//  Copyright © 2025 ReallyMe LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
//  ML-DSA-87 attestation generator for DID:me
//
//  IMPORTANT:
//  • Root ML-DSA-87 key signs the *raw Core CBOR bytes*
//  • Verification must also use the Core CBOR bytes
//

import Foundation
import SwiftDilithium

public enum DIDAttestation {

    // MARK: - Errors

    public enum Error: Swift.Error {
        case emptyCoreCBOR
        case emptySecretKeyPEM
        case emptyChallenge
        case emptySignature
        case emptyPublicKeyData
        case invalidPublicKey
    }

    // MARK: - Attestation Creation (ROOT key)

    /// Create ML-DSA-87 attestation over the *Core CBOR* bytes.
    public static func create(
        coreCBOR: Data,
        secretKeyPEM: String,
        vmFragment: String
    ) throws -> Attestation {

        // Harden: require non-empty CBOR + secret PEM
        guard !coreCBOR.isEmpty else {
            throw Error.emptyCoreCBOR
        }
        guard !secretKeyPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Error.emptySecretKeyPEM
        }

        let sk = try SecretKey(pem: secretKeyPEM)

        // The exact CBOR bytes are signed.
        // This produces canonical DID anchoring.
        let sigBytes = sk.Sign(
            message: Array(coreCBOR),
            randomize: true
        )

        return Attestation(
            alg: "ML-DSA-87",
            vm: vmFragment,
            sig: DIDEncodingUtils.base64urlEncode(Data(sigBytes))
        )
    }

    // MARK: - Raw ML-DSA signing (auth key)
    // Unrelated to DID anchoring — used for challenges, etc.

    public static func signMLDSA(
        challenge: Data,
        secretKeyPEM: String
    ) throws -> Data {

        guard !challenge.isEmpty else {
            throw Error.emptyChallenge
        }
        guard !secretKeyPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Error.emptySecretKeyPEM
        }

        let sk = try SecretKey(pem: secretKeyPEM)
        let sig = sk.Sign(
            message: Array(challenge),
            randomize: true
        )
        return Data(sig)
    }

    // MARK: - Verification

    /// Verify ML-DSA-87 signature over *Core CBOR*.
    ///
    /// publicKeyData = multicodec bytes: uvarint(codec) + DER public key
    public static func verifyMLDSA(
        message: Data,
        signature: Data,
        publicKeyData: Data
    ) throws -> Bool {

        guard !message.isEmpty else {
            throw Error.emptyCoreCBOR
        }
        guard !signature.isEmpty else {
            throw Error.emptySignature
        }
        guard !publicKeyData.isEmpty else {
            throw Error.emptyPublicKeyData
        }

        // publicKeyData = RAW ML-DSA public key bytes (dil87RootPk.keyBytes)
        let pk = try PublicKey(keyBytes: [UInt8](publicKeyData))

        let sigBytes = [UInt8](signature)
        let msgBytes = [UInt8](message)

        return pk.Verify(
            message: msgBytes,
            signature: sigBytes
        )
    }
}
