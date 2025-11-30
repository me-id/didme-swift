//
//  KeyGenerator.swift
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
//
//  Generates all asymmetric key material needed for a DID:
//    • Ed25519 (signing)
//    • P-256 (signing; Secure Enclave on device, software on simulator)
//    • ML-DSA-87 root + auth keys
//    • ML-KEM-1024 (KEM keypair)
//    • X25519 (key agreement)
//
//  Returns a DIDKeyMaterial struct that can be fed into DIDGenerator.
//

import Foundation
import CryptoKit
import SwiftDilithium
import SwiftKyber

public enum DIDKeyGenerator {

    /// Main entrypoint: generate key material appropriate for the current environment
    /// (Secure Enclave on device, software-only on simulator).
    public static func generateKeyMaterialForCurrentEnvironment(
        p256Tag: String = "com.reallyme.did.p256"
    ) throws -> DIDKeyMaterial {
        #if targetEnvironment(simulator)
        return try generateKeyMaterial(isSimulator: true, p256Tag: p256Tag)
        #else
        return try generateKeyMaterial(isSimulator: false, p256Tag: p256Tag)
        #endif
    }

    private static func compressedP256X963(_ x963: Data) -> Data {
        // 65 bytes: 0x04 || X(32) || Y(32)
        precondition(x963.count == 65 && x963.first == 0x04)
        let x = x963[1...32]
        let yLast = x963[64]
        let prefix: UInt8 = (yLast & 1) == 0 ? 0x02 : 0x03
        return Data([prefix]) + x             // 33 bytes (SEC1 compressed)
    }

    private static func compressedP256(_ pub: P256.Signing.PublicKey) -> Data {
        compressedP256X963(pub.x963Representation)
    }

    /// Generate full DIDKeyMaterial.
    ///
    /// - Parameters:
    ///   - isSimulator: If true, P-256 uses software keys; if false, uses Secure Enclave.
    ///   - p256Tag: application tag for Secure Enclave P-256 private key (ignored on simulator).
    ///
    public static func generateKeyMaterial(
        isSimulator: Bool,
        p256Tag: String
    ) throws -> DIDKeyMaterial {

        // ----------------------------------------------------
        // Ed25519 (signing)
        // ----------------------------------------------------
        let ed25519Priv = Curve25519.Signing.PrivateKey()
        let ed25519Pub  = Data(ed25519Priv.publicKey.rawRepresentation)

        // ----------------------------------------------------
        // P-256
        //   • Simulator: software CryptoKit key
        //   • Device: Secure Enclave key (X9.62 P-256)
        // ----------------------------------------------------
        var p256SoftwarePriv: P256.Signing.PrivateKey? = nil
        var p256SecureEnclavePriv: SecKey? = nil
        let p256Pub: Data

        if isSimulator {
            // Software-only P-256
            let sk = P256.Signing.PrivateKey()
            p256SoftwarePriv = sk
            p256Pub = compressedP256(sk.publicKey)
        } else {
            // Secure Enclave-backed P-256 key
            let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage],
                nil
            )!

            let tagData = p256Tag.data(using: .utf8)!

            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: true,
                    kSecAttrApplicationTag as String: tagData,
                    kSecAttrAccessControl as String: access
                ]
            ]

            var error: Unmanaged<CFError>?
            guard let seKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                throw error!.takeRetainedValue() as Error
            }

            p256SecureEnclavePriv = seKey

            guard let pubKey = SecKeyCopyPublicKey(seKey) else {
                throw DIDKeyGenError.invalidDER("Failed to extract P-256 public key from Secure Enclave")
            }

            var pubError: Unmanaged<CFError>?
            guard let x963Data = SecKeyCopyExternalRepresentation(pubKey, &pubError) as Data? else {
                throw pubError!.takeRetainedValue() as Error
            }

            p256Pub = compressedP256X963(x963Data)
        }

        // ----------------------------------------------------
        // ML-DSA-87 Root
        // ----------------------------------------------------
        let (dil87RootSk, dil87RootPk) =
            SwiftDilithium.Dilithium.GenerateKeyPair(kind: .ML_DSA_87)

        let mldsa87RootPubRAW = Data(dil87RootPk.keyBytes)
        let mldsa87RootSecretPEM = dil87RootSk.pem

        // ----------------------------------------------------
        // ML-DSA-87 Auth
        // ----------------------------------------------------
        let (dil87AuthSk, dil87AuthPk) =
            SwiftDilithium.Dilithium.GenerateKeyPair(kind: .ML_DSA_87)

        let mldsa87AuthPubRAW = Data(dil87AuthPk.keyBytes)
        let mldsa87AuthSecretPEM = dil87AuthSk.pem

        // ----------------------------------------------------
        // ML-KEM-1024 (Encapsulation pub, decapsulation priv)
        // ----------------------------------------------------
        let (kybEnc, kybDec) =
            SwiftKyber.Kyber.GenerateKeyPair(kind: .K1024)

        let mlkem1024PubRAW = Data(kybEnc.keyBytes)
        let mlkem1024SecretPEM = kybDec.pem

        // ----------------------------------------------------
        // X25519
        // ----------------------------------------------------
        let x25519Priv = try Curve25519.KeyAgreement.PrivateKey()
        let x25519Pub  = Data(x25519Priv.publicKey.rawRepresentation)

        // ----------------------------------------------------
        // Assemble DIDKeyMaterial (with metadata)
        // ----------------------------------------------------
        let material = DIDKeyMaterial(
            // PUBLIC
            ed25519Pub: ed25519Pub,
            p256Pub: p256Pub,
            mldsa87RootPub: mldsa87RootPubRAW,
            mldsa87AuthPub: mldsa87AuthPubRAW,
            mlkem1024Pub: mlkem1024PubRAW,
            x25519Pub: x25519Pub,

            // OPTIONAL BLOCKCHAIN PUBLIC KEYS
            btcSecp256k1Pub: nil,
            ethSecp256k1Pub: nil,
            solEd25519Pub: nil,
            avaxSecp256k1Pub: nil,

            // PRIVATE
            ed25519Secret: ed25519Priv,
            x25519Secret: x25519Priv,
            p256SoftwarePrivateKey: p256SoftwarePriv,
            p256SecureEnclavePrivateKey: p256SecureEnclavePriv,
            mldsa87RootSecretPEM: mldsa87RootSecretPEM,
            mldsa87AuthSecretPEM: mldsa87AuthSecretPEM,
            mlkem1024SecretPEM: mlkem1024SecretPEM,

            // OPTIONAL BLOCKCHAIN PRIVATE KEYS
            btcSecp256k1Secret: nil,
            ethSecp256k1Secret: nil,
            solEd25519Secret: nil,
            avaxSecp256k1Secret: nil,

            // SECURITY METADATA
            isHardwareBacked: !isSimulator,
            isBiometricProtected: false,
            userVerificationMethod: nil
        )

        return material
    }

    // MARK: - Internal helpers

    /// Convert PEM-encoded key to DER bytes.
    private static func pemToDer(_ pem: String) -> Data {
        let lines = pem
            .components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }

        return Data(base64Encoded: lines.joined()) ?? Data()
    }

    /// Ensure DER extracted from PEM is valid
    private static func validateNotEmptyDER(_ der: Data, label: String) throws {
        if der.isEmpty {
            throw DIDKeyGenError.invalidDER("\(label) DER is empty or invalid")
        }
    }
}

/// Errors thrown during key generation
public enum DIDKeyGenError: Error {
    case invalidDER(String)
}
