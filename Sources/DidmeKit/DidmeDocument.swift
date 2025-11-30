//
//  DidmeDocument.swift
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
//  Canonical DID Document model for did:me.
//
//  This struct matches the JSON-LD / JSON data model required by:
//    • W3C DID Core
//    • did:me (your method)
//    • Your custom keyHistory/currentCore/CID-based core signing
//
//  IMPORTANT:
//    All fields should remain Codable and JSON-safe.
//    JCS canonicalization is applied after encoding.
//

import Foundation

public struct DIDDocument: Codable {
    
    // MARK: - Core DID fields
    
    /// @context values (e.g. DID Core v1 + Multikey + did:me namespace).
    public var context: [String]
    
    /// DID identifier (e.g. "did:me:xxxx").
    public var id: String
    
    /// Controller of this DID (in your method, same as id).
    public var controller: String
    
    /// Additional identity aliases .
    public var alsoKnownAs: [String]
    
    ///monotonic intiger increment
    public var sequence: Int
    
    /// CID of previous core(s) in order or nil
    public var prev: String?
    
    
    // MARK: - Device / Security Metadata (optional, signed as part of core CBOR)
    
    /// Whether the DID’s update keys are backed by a hardware Secure Enclave or equivalent.
    /// If true, the P-256 key was generated inside a hardware security module.
    public var hardwareBound: Bool?
    
    /// Whether use of the update key required biometric verification (Face ID / Touch ID).
    /// This is determined by the app at creation time and injected into the DID.
    public var biometricProtected: Bool?
    
    /// The active user verification method used on the device.
    /// Allowed values defined by did:me context:
    ///   "face", "fingerprint", "pin", "passcode", "password",
    ///   "iris", "voice", "pattern", "none".
    public var userVerificationMethod: String?
    
    /// The device model identifier (e.g. "iPhone16,2").
    /// Useful for auditing key provenance and device security posture.
    public var deviceModel: String?
    
    // MARK: - CoreEnvelope / CID chain
    
    /// Base64URL-encoded CoreEnvelope CBOR (the actual signed content).
    public var coreCbor: String
    
    /// CIDv1 of the latest core object (content-addressed).
    /// Non-optional: required for DID updates, proofs, and rotation.
    public var currentCore: String
    
    /// Ordered list of all past core CIDs (latest is `currentCore`).
    public var keyHistory: [String]
    
    // MARK: - Verification Keys
    
    /// Full verificationMethod array (VM entries with multikey encodings).
    public var verificationMethod: [VerificationMethod]
    
    /// Authentication VM references (e.g. ["#ed25519", "#mldsa87-auth"]).
    public var authentication: [String]
    
    /// AssertionMethod VM references (e.g. for credential issuance).
    public var assertionMethod: [String]
    
    /// Keys allowed for DID update authorization.
    public var capabilityInvocation: [String]
    
    /// Key agreement methods (X25519 + ML-KEM).
    public var keyAgreement: [String]
    
    // MARK: - Services / Policy / Integrity
    
    /// DID service endpoints (hub, wallet, messaging, passkey, etc.)
    public var service: [Service]
    
    /// Allowed verificationMethods for key rotations.
    public var updatePolicy: UpdatePolicy
    
    /// ML-DSA-87 attestations over the core CBOR.
    public var attestations: [Attestation]
    
    /// P-256 DataIntegrityProof over the core CID.
    public var proof: Proof
    
    
    // 🔑 Map Swift `context` -> JSON "@context"
    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case id, controller, alsoKnownAs
        case sequence
        case prev
        case hardwareBound, biometricProtected, userVerificationMethod, deviceModel
        case coreCbor, currentCore, keyHistory
        case verificationMethod, authentication, assertionMethod, capabilityInvocation, keyAgreement
        case service, updatePolicy, attestations, proof
    }
    
    // MARK: - Init
    
    public init(
        context: [String],
        id: String,
        controller: String,
        alsoKnownAs: [String],
        sequence: Int,
        prev: String?,
        hardwareBound: Bool? = nil,
        biometricProtected: Bool? = nil,
        userVerificationMethod: String? = nil,
        deviceModel: String? = nil,
        coreCbor: String,
        currentCore: String,
        keyHistory: [String],
        verificationMethod: [VerificationMethod],
        authentication: [String],
        assertionMethod: [String],
        capabilityInvocation: [String],
        keyAgreement: [String],
        service: [Service],
        updatePolicy: UpdatePolicy,
        attestations: [Attestation],
        proof: Proof
    ) {
        self.context = context
        self.id = id
        self.controller = controller
        self.alsoKnownAs = alsoKnownAs
        self.sequence = Int(sequence)
        self.prev = prev
        
        self.hardwareBound = hardwareBound
        self.biometricProtected = biometricProtected
        self.userVerificationMethod = userVerificationMethod
        self.deviceModel = deviceModel
        
        self.coreCbor = coreCbor
        self.currentCore = currentCore
        self.keyHistory = keyHistory
        self.verificationMethod = verificationMethod
        self.authentication = authentication
        self.assertionMethod = assertionMethod
        self.capabilityInvocation = capabilityInvocation
        self.keyAgreement = keyAgreement
        self.service = service
        self.updatePolicy = updatePolicy
        self.attestations = attestations
        self.proof = proof
    }
}   // end DIDDocument


// MARK: - VerificationMethod

public struct VerificationMethod: Codable {
    public var id: String
    public var controller: String
    public var type: String
    /// Required cryptosuite indicator (e.g. "ML-DSA-87", "ES256", etc.)
    public var algorithm: DIDAlgorithm
    /// Multibase-encoded public key (required).
    public var publicKeyMultibase: String
}

// MARK: - Service

public struct Service: Codable {
    public var id: String
    public var type: String
    public var serviceEndpoint: ServiceEndpoint
    public var version: String?
    
    public enum ServiceEndpoint: Codable {
        case uri(String)
        case map([String: String])

        public init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if let uri = try? c.decode(String.self) {
                self = .uri(uri)
            } else if let map = try? c.decode([String: String].self) {
                self = .map(map)
            } else {
                throw DecodingError.dataCorruptedError(
                    in: c,
                    debugDescription: "Invalid serviceEndpoint"
                )
            }
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.singleValueContainer()
            switch self {
            case .uri(let s): try c.encode(s)
            case .map(let m): try c.encode(m)
            }
        }
    }
}

// MARK: - UpdatePolicy
public struct UpdatePolicy: Codable {
    /// VerificationMethods permitted to rotate keys (e.g. "#mldsa87-root").
    public var allowedVerificationMethods: [String]
}

// MARK: - Attestation

/// ML-DSA-87 attestation of the CoreEnvelope CBOR.
public struct Attestation: Codable {
    public var alg: String          // e.g. "ML-DSA-87"
    public var vm: String           // e.g. "#mldsa87-root"
    public var sig: String          // base64url-encoded signature
}

// MARK: - Proof

/// P-256 DataIntegrityProof over the core CID for DID updates.
public struct Proof: Codable {
    public var id: String?
    public var type: String         // e.g. "DataIntegrityProof"
    public var cryptosuite: String? // e.g. "es256-jws-cid-2025"
    public var proofPurpose: String // e.g. "assertionMethod"
    public var verificationMethod: String?
    public var created: String?     // ISO timestamp
    public var jws: String?         // compact JWS (proof signature)
}
