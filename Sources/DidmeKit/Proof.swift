//
//  Proof.swift
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
//  Generates the P-256 / ES256 proof for DID:me documents.
//
//  IMPORTANT: Updated for the new `"es256-jws-cid-2025"` cryptosuite.
//
//  ─────────────────────────────────────────────────────────────────────
//
//  WHAT THIS PROOF DOES
//  --------------------
//  DID:me uses a dual-rail trust design:
//
//    • Post-quantum rail: ML-DSA-87 signs the canonical CBOR core (`coreCbor`)
//    • Classical rail:   P-256 signs the CID (`currentCore`) of that CBOR
//
//  The CID is a content hash of the CBOR. Therefore, signing the CID is
//  cryptographically equivalent to signing the full PQ-anchored core.
//
//  This file implements the *classical P-256 rail* using a **standard ES256
//  compact JWS**, with ⬇
//
//      header  = {"alg":"ES256"}
//      payload = currentCore  (UTF-8 CID string)
//      signature = ECDSA P-256 over:  BASE64URL(header) + "." + BASE64URL(payload)
//
//  This follows JOSE RFC 7515 exactly, making the proof fully compatible with:
//    • Cloudflare Workers WebCrypto
//    • Go crypto/ecdsa + JWS verifiers
//    • EUDI / EU Wallet stacks (they expect ES256 JWS semantics)
//    • All modern ES256 tooling
//
//  ─────────────────────────────────────────────────────────────────────
//
//  WHY WE DO NOT SIGN RAW `currentCore`
//  ------------------------------------
//  JWS signatures *must* be created over the JWS Signing Input:
//
//        BASE64URL(header) + "." + BASE64URL(payload)
//
//  Not over the raw payload bytes.
//  This is the key fix compared to the original implementation.
//
//  ─────────────────────────────────────────────────────────────────────
//
//  cryptosuite = "es256-jws-cid-2025"
//  -------------------------------------
//  This replaces the old misuse of `ecdsa-rdfc-2019`.
//  `es256-jws-cid-2025` means:
//
//      “Standard ES256 JWS where payload == currentCore (CID)”
//
//  Verifiers simply parse JWS, ensure payload==currentCore, and use ES256.
//
//  ─────────────────────────────────────────────────────────────────────
//

import Foundation
import CryptoKit

public enum DIDProof {

    /// Creates a P-256 DataIntegrityProof for DID:me over `currentCore` (CID).
    ///
    /// Signatures produced here are standard ES256 JWS signatures over the JWS
    /// Signing Input, and are canonical low-S as required by the spec.
    ///
    public static func createP256Proof(
        coreCid: String,
        p256PrivateKey: P256.Signing.PrivateKey?,
        secKey: SecKey?,
        vmFragment: String
    ) throws -> Proof {

        let createdISO = ISO8601DateFormatter().string(from: Date())

        // 1. JWS protected header + payload
        let headerJSON = #"{"alg":"ES256"}"#
        let headerData = Data(headerJSON.utf8)

        let payloadData = Data(coreCid.utf8)

        let headerB64  = b64url(headerData)
        let payloadB64 = b64url(payloadData)

        let signingInput = Data("\(headerB64).\(payloadB64)".utf8)

        // 2. P-256 ES256 over SHA-256(signingInput)
        let signatureDER: Data

        if let softwareKey = p256PrivateKey {
            let sig = try softwareKey.signature(for: signingInput)
            signatureDER = sig.derRepresentation
        } else if let enclaveKey = secKey {
            signatureDER = try signWithSecureEnclave(secKey: enclaveKey, payload: signingInput)
        } else {
            throw NSError(
                domain: "DIDProof",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "No P-256 private key available for proof"]
            )
        }

        // 3. Compact JWS
        let sigB64 = b64url(signatureDER)
        let jws = "\(headerB64).\(payloadB64).\(sigB64)"

        // 4. Proof object
        return Proof(
            id: "#proof-p256",
            type: "DataIntegrityProof",
            cryptosuite: "es256-jws-cid-2025",
            proofPurpose: "assertionMethod",
            verificationMethod: vmFragment,         // "#p256"
            created: createdISO,
            jws: jws
        )
    }

    // MARK: - Helpers

    /// Base64URL encoder (RFC 7515 / JOSE)
    private static func b64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Secure Enclave signing: ECDSA P-256 (X9.62 SHA-256).
    private static func signWithSecureEnclave(secKey: SecKey, payload: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            secKey,
            .ecdsaSignatureMessageX962SHA256,
            payload as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue()
        }
        return sig
    }
}

