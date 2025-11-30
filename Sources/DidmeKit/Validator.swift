//
//  Validator.swift
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

import Foundation
import CryptoKit

public enum DIDVerifier {

    public struct VerificationResult {
        public let isValid: Bool
        public let errors: [String]
    }

    // ============================================================
    // MARK: 0. DID:me Structural Validation
    // ============================================================

    private static func verifyStructure(_ doc: DIDDocument) -> String? {

        // ---------- @context (required, not optional) ----------
        let expectedContext = [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            "https://w3id.org/security/suites/secp256r1-2019/v1",
            "https://me-id.org/ns/did-me/v1"
        ]
        if doc.context != expectedContext {
            return "@context mismatch or wrong ordering"
        }

        // ---------- id + controller ----------
        if doc.controller != doc.id {
            return "controller must equal id"
        }
        if !doc.id.starts(with: "did:me:") {
            return "id must start with did:me:"
        }

        // ---------- currentCore ----------
        let currentCore = doc.currentCore

        // ---------- coreCbor ----------
        if doc.coreCbor.isEmpty {
            return "coreCbor is missing or empty"
        }

        // ---------- sequence / prev / keyHistory ----------

        let history = doc.keyHistory
        let sequence = doc.sequence

        // keyHistory MUST NOT contain currentCore
        if history.contains(currentCore) {
            return "keyHistory MUST NOT contain currentCore CID"
        }

        // sequence MUST equal history.count + 1
        if sequence != history.count + 1 {
            return "sequence MUST equal keyHistory.count + 1"
        }

        // prev rules:
        // - if sequence == 1 → prev MUST be nil
        // - if sequence > 1  → prev MUST equal last history entry
        if sequence == 1 {
            if doc.prev != nil {
                return "prev MUST be nil when sequence == 1"
            }
            // history SHOULD be empty when sequence==1
            if !history.isEmpty {
                return "keyHistory MUST be empty when sequence == 1"
            }
        } else {
            guard let prev = doc.prev else {
                return "prev MUST be present when sequence > 1"
            }
            if history.last != prev {
                return "prev MUST equal last entry in keyHistory"
            }
        }

        // ---------- verificationMethod (non-optional array) ----------
        let requiredVMs = Set([
            "#mldsa87-root",
            "#ed25519",
            "#p256",
            "#mldsa87-auth",
            "#mlkem1024",
            "#x25519"
        ])
        let vmIDs = Set(doc.verificationMethod.map { $0.id })

        for req in requiredVMs {
            if !vmIDs.contains(req) {
                return "Missing required verificationMethod \(req)"
            }
        }

        // ---------- authentication (non-optional array) ----------
        if !doc.authentication.contains("#ed25519") ||
           !doc.authentication.contains("#mldsa87-auth") {
            return "authentication must contain #ed25519 and #mldsa87-auth"
        }

        // ---------- assertionMethod ----------
        if !doc.assertionMethod.contains("#p256") {
            return "assertionMethod must include #p256"
        }

        // ---------- capabilityInvocation ----------
        if !doc.capabilityInvocation.contains("#mldsa87-root") {
            return "capabilityInvocation must include #mldsa87-root"
        }

        // ---------- keyAgreement ----------
        if !doc.keyAgreement.contains("#x25519") ||
           !doc.keyAgreement.contains("#mlkem1024") {
            return "keyAgreement must include #x25519 and #mlkem1024"
        }

        // ---------- updatePolicy ----------
        let policy = doc.updatePolicy
        if !policy.allowedVerificationMethods.contains("#mldsa87-root") {
            return "updatePolicy.allowedVerificationMethods must contain #mldsa87-root"
        }

        // ---------- attestations ----------
        let atts = doc.attestations
        if atts.isEmpty {
            return "attestations must have at least one entry"
        }
        if atts[0].vm != "#mldsa87-root" {
            return "attestations[0].vm must be #mldsa87-root"
        }

        // ---------- proof ----------
        let proof = doc.proof
        if proof.verificationMethod != "#p256" {
            return "proof.verificationMethod must be #p256"
        }

        return nil
    }

    // ============================================================
    // MARK: Public Entry
    // ============================================================

    public static func verify(document: DIDDocument, jcsData: Data) -> VerificationResult {
        var errors: [String] = []

        if let e = verifyStructure(document) { errors.append(e) }
        if let e = verifyCanonical(document: document, jcsData: jcsData) { errors.append(e) }
        if let e = verifyRootAttestation(document) { errors.append(e) }
        if let e = verifyP256Proof(document) { errors.append(e) }

        return VerificationResult(isValid: errors.isEmpty, errors: errors)
    }

    // ============================================================
    // MARK: 1. JCS canonical check
    // ============================================================

    private static func verifyCanonical(document: DIDDocument, jcsData: Data) -> String? {
        do {
            let reencoded = try DIDJCS.canonicalData(from: document)
            if reencoded != jcsData {
                return "JCS mismatch: canonical JSON does not match stored"
            }
        } catch {
            return "JCS encoding failed: \(error)"
        }
        return nil
    }

    // ============================================================
    // MARK: 2. ML-DSA-87 attestation
    // ============================================================

    private static func verifyRootAttestation(_ doc: DIDDocument) -> String? {

        // 1. Must have at least one attestation
        guard let att = doc.attestations.first else {
            return "Missing ML-DSA-87 attestation"
        }

        // 2. Locate the #mldsa87-root verification method
        guard
            let vm = doc.verificationMethod.first(where: { $0.id == "#mldsa87-root" }),
            vm.algorithm == .mldsa87,
            let pkMulti = DIDMultibase.decode(vm.publicKeyMultibase)
        else {
            return "Invalid or missing #mldsa87-root verificationMethod"
        }

        // 3. Decode multicodec prefix using your enum
        guard let (codec, rawKey) = decodeMulticodec(pkMulti) else {
            return "Invalid ML-DSA-87 multicodec encoding"
        }

        guard let keyType = MulticodecKeyType(rawValue: UInt16(codec)) else {
            return "Unknown multicodec type for ML-DSA-87"
        }

        guard keyType == .mldsa87Pub else {
            return "Invalid ML-DSA-87 multicodec (expected mldsa87Pub)"
        }

        // 4. Decode CBOR bytes of the signed core object
        guard let coreCborData = DIDEncodingUtils.base64urlDecode(doc.coreCbor) else {
            return "Invalid coreCbor (not valid base64url)"
        }

        let message = coreCborData

        // 5. Decode and verify ML-DSA-87 signature
        do {
            guard let sig = DIDEncodingUtils.base64urlDecode(att.sig) else {
                return "Invalid ML-DSA-87 signature encoding"
            }

            let ok = try DIDAttestation.verifyMLDSA(
                message: message,
                signature: sig,
                publicKeyData: rawKey   // raw ML-DSA public key bytes
            )

            if !ok {
                return "ML-DSA-87 signature verification failed"
            }

        } catch {
            return "ML-DSA-87 attestation error: \(error)"
        }

        return nil
    }

    // ============================================================
    // MARK: 3. P-256 ES256 proof
    // ============================================================
    
    private static func verifyP256Proof(_ doc: DIDDocument) -> String? {

        let proof = doc.proof

        // 1. Check that proof references #p256 VM
        guard proof.verificationMethod == "#p256" else {
            return "P-256 proof must reference #p256"
        }

        // 2. Locate the #p256 verification method
        guard
            let vm = doc.verificationMethod.first(where: { $0.id == "#p256" }),
            vm.algorithm == .es256,
            let pkMulti = DIDMultibase.decode(vm.publicKeyMultibase)
        else {
            return "Invalid #p256 verificationMethod"
        }

        // 3. Decode multicodec
        guard let (codec, rawKey) = decodeMulticodec(pkMulti) else {
            return "Malformed multicodec prefix on #p256"
        }

        // 4. Enforce correct multicodec type using enum
        guard let keyType = MulticodecKeyType(rawValue: UInt16(codec)) else {
            return "Unknown multicodec type for #p256"
        }

        guard keyType == .p256Pub else {
            return "Invalid multicodec (expected p256Pub)"
        }

        // 5. Construct P-256 public key from compressed bytes
        guard let pub = try? P256.Signing.PublicKey(compressedRepresentation: rawKey) else {
            return "Could not construct P-256 public key (compressed)"
        }

        // ------------------------------
        // JWS ("es256-jws-cid-2025") verification
        // ------------------------------

        guard let jws = proof.jws else {
            return "Missing JWS string"
        }

        let parts = jws.split(separator: ".")
        guard parts.count == 3 else { return "Invalid JWS" }

        let headerB64 = String(parts[0])
        let payloadB64 = String(parts[1])
        let sigB64 = String(parts[2])

        // Decode and check JWS header
        guard
            let headerData = DIDEncodingUtils.base64urlDecode(headerB64),
            let headerJSON = try? JSONSerialization.jsonObject(with: headerData) as? [String:Any],
            let alg = headerJSON["alg"] as? String,
            alg == DIDAlgorithm.es256.rawValue  // == "ES256"
        else {
            return "Invalid or unexpected JWS header"
        }

        // Decode payload and enforce: payload == currentCore
        guard
            let payloadData = DIDEncodingUtils.base64urlDecode(payloadB64),
            let payloadStr = String(data: payloadData, encoding: .utf8)
        else {
            return "Invalid JWS payload"
        }

        guard payloadStr == doc.currentCore else {
            return "JWS payload mismatch: must equal currentCore"
        }

        // Decode DER signature
        guard
            let sigDER = DIDEncodingUtils.base64urlDecode(sigB64),
            let sig = try? P256.Signing.ECDSASignature(derRepresentation: sigDER)
        else {
            return "Invalid JWS signature (DER)"
        }

        // Build signing input: base64url(header) + "." + base64url(payload)
        let signingInput = Data((headerB64 + "." + payloadB64).utf8)

        // Verify ECDSA signature
        do {
            if try !pub.isValidSignature(sig, for: signingInput) {
                return "Invalid P-256 JWS signature"
            }
        } catch {
            return "P-256 verification error: \(error)"
        }

        return nil
    }

    // ============================================================
    // MARK: Helpers
    // ============================================================

    private static func jwsExtractSignature(_ jws: String?) -> Data? {
        guard let jws else { return nil }
        let parts = jws.split(separator: ".")
        guard parts.count == 3 else { return nil }
        return DIDEncodingUtils.base64urlDecode(String(parts[2]))
    }

    private static func decodeMulticodec(_ data: Data) -> (Int, Data)? {
        var value = 0
        var shift = 0
        var index = 0
        let bytes = [UInt8](data)

        while index < bytes.count {
            let b = bytes[index]
            value |= Int(b & 0x7F) << shift
            index += 1

            if (b & 0x80) == 0 {
                let payload = data.dropFirst(index)
                return (value, Data(payload))
            }
            shift += 7
            if shift > 28 { return nil }
        }

        return nil
    }
}
