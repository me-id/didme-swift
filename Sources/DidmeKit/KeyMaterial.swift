//
//  KeyMaterial.swift
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
////
//  Aggregates all keypairs required to construct and maintain a DID.
//  - PUBLIC keys appear inside the DID Document.
//  - PRIVATE keys are fed into the Keybag (via KeybagService) for secure storage.
//  - Some algorithms use CryptoKit keys, others use PEM-based wrappers.
//  - P-256 can be Secure Enclave–backed on device and software-backed in simulator.
//
//  IMPORTANT:
//  - No persistent storage should ever use this struct directly.
//  - Use KeybagService to persist private keys.
//  - Public keys are safe to place in DID Documents and DIDStore (JCS-JSON).
//

import Foundation
import CryptoKit

public struct DIDKeyMaterial {

    // ============================================================
    // MARK: - PUBLIC Keys (included in DID Document)
    // ============================================================
    //
    // These are the public keys published inside the DID Document.
    // They must be stable representations (raw or DER-encoded) that
    // feed DIDMultikey and DIDGenerator.
    //
    // ============================================================

    public var ed25519Pub: Data          // Ed25519 signing public key
    public var p256Pub: Data             // P-256 signing/verification public key
    public var mldsa87RootPub: Data      // ML-DSA-87 "root" public key
    public var mldsa87AuthPub: Data      // ML-DSA-87 "auth" public key
    public var mlkem1024Pub: Data        // ML-KEM-1024 encapsulation public key
    public var x25519Pub: Data           // X25519 key agreement public key

    // Optional blockchain public keys
    public var btcSecp256k1Pub: Data?
    public var ethSecp256k1Pub: Data?
    public var solEd25519Pub: Data?
    public var avaxSecp256k1Pub: Data?


    // ============================================================
    // MARK: - PRIVATE Keys (never published)
    // ============================================================
    //
    // These keys MUST be placed into the Keybag via KeybagService.
    //
    // After doing so, the app should NOT store this structure persistently.
    //
    // ============================================================

    // CryptoKit traditional asymmetric keys
    public var ed25519Secret: Curve25519.Signing.PrivateKey
    public var x25519Secret: Curve25519.KeyAgreement.PrivateKey

    // --- P-256
    //
    // NOTE:
    // Only one of these will be non-nil:
    //   • Simulator: p256SoftwarePrivateKey
    //   • Device:    p256SecureEnclavePrivateKey
    //
    // Software key is exported raw.
    // Secure Enclave key must be exported in a wrapped form if stored at all.
    //
    public var p256SoftwarePrivateKey: P256.Signing.PrivateKey?
    public var p256SecureEnclavePrivateKey: SecKey?

    // --- ML-DSA-87 (Post-quantum)
    // Private keys in PEM format (Dilithium library uses PEM export)
    public var mldsa87RootSecretPEM: String
    public var mldsa87AuthSecretPEM: String

    // --- ML-KEM-1024
    // Private decapsulation key in PEM format
    public var mlkem1024SecretPEM: String?

    // Optional blockchain keys (raw)
    public var btcSecp256k1Secret: Data?
    public var ethSecp256k1Secret: Data?
    public var solEd25519Secret: Data?
    public var avaxSecp256k1Secret: Data?


    // ============================================================
    // MARK: - SECURITY METADATA (optional)
    // ============================================================
    //
    // These fields describe the origin and protection level of the
    // P-256 update key. They are determined by the *app layer* and
    // injected into the DID Core CBOR during DID generation.
    //
    // The DIDKit package sets these to defaults (false/nil).
    // The app overrides them when Secure Enclave or biometrics are used.
    //
    // ============================================================

    /// True if the update key was generated inside Secure Enclave or equivalent.
    public var isHardwareBacked: Bool

    /// True if key usage required biometric authentication (FaceID / TouchID).
    public var isBiometricProtected: Bool

    /// The active user verification method (face, fingerprint, pin, etc.)
    public var userVerificationMethod: String?


    // ============================================================
    // MARK: - Initializer
    // ============================================================

    public init(
        // PUBLIC keys
        ed25519Pub: Data,
        p256Pub: Data,
        mldsa87RootPub: Data,
        mldsa87AuthPub: Data,
        mlkem1024Pub: Data,
        x25519Pub: Data,
        btcSecp256k1Pub: Data? = nil,
        ethSecp256k1Pub: Data? = nil,
        solEd25519Pub: Data? = nil,
        avaxSecp256k1Pub: Data? = nil,

        // PRIVATE keys
        ed25519Secret: Curve25519.Signing.PrivateKey,
        x25519Secret: Curve25519.KeyAgreement.PrivateKey,
        p256SoftwarePrivateKey: P256.Signing.PrivateKey? = nil,
        p256SecureEnclavePrivateKey: SecKey? = nil,
        mldsa87RootSecretPEM: String,
        mldsa87AuthSecretPEM: String,
        mlkem1024SecretPEM: String? = nil,
        btcSecp256k1Secret: Data? = nil,
        ethSecp256k1Secret: Data? = nil,
        solEd25519Secret: Data? = nil,
        avaxSecp256k1Secret: Data? = nil,

        // SECURITY METADATA
        isHardwareBacked: Bool = false,
        isBiometricProtected: Bool = false,
        userVerificationMethod: String? = nil
    ) {
        // Public
        self.ed25519Pub = ed25519Pub
        self.p256Pub = p256Pub
        self.mldsa87RootPub = mldsa87RootPub
        self.mldsa87AuthPub = mldsa87AuthPub
        self.mlkem1024Pub = mlkem1024Pub
        self.x25519Pub = x25519Pub

        self.btcSecp256k1Pub = btcSecp256k1Pub
        self.ethSecp256k1Pub = ethSecp256k1Pub
        self.solEd25519Pub = solEd25519Pub
        self.avaxSecp256k1Pub = avaxSecp256k1Pub

        // Private
        self.ed25519Secret = ed25519Secret
        self.x25519Secret = x25519Secret
        self.p256SoftwarePrivateKey = p256SoftwarePrivateKey
        self.p256SecureEnclavePrivateKey = p256SecureEnclavePrivateKey

        self.mldsa87RootSecretPEM = mldsa87RootSecretPEM
        self.mldsa87AuthSecretPEM = mldsa87AuthSecretPEM
        self.mlkem1024SecretPEM = mlkem1024SecretPEM

        self.btcSecp256k1Secret = btcSecp256k1Secret
        self.ethSecp256k1Secret = ethSecp256k1Secret
        self.solEd25519Secret = solEd25519Secret
        self.avaxSecp256k1Secret = avaxSecp256k1Secret

        // Metadata
        self.isHardwareBacked = isHardwareBacked
        self.isBiometricProtected = isBiometricProtected
        self.userVerificationMethod = userVerificationMethod
    }
}
