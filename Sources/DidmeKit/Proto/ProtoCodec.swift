//  ProtoCodec
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

import Foundation
import SwiftProtobuf

// ------------------------------------------------------------
// TYPEALIASES (adjust only if your module name differs)
// ------------------------------------------------------------
typealias PbDIDDocument = Didme_DIDDocument
typealias PbVMKey = Didme_VMKey
typealias PbService = Didme_Service
typealias PbAttestation = Didme_Attestation
typealias PbProof = Didme_Proof
typealias PbDomainVerification = Didme_DomainVerification
typealias PbUpdatePolicy = Didme_UpdatePolicy
typealias PbAlgorithm = Didme_Algorithm
typealias PbKeyType = Didme_KeyType
typealias PbDVType = Didme_DomainVerificationType

// ------------------------------------------------------------
// ENUM MAPPING HELPERS (MATCH GENERATED PROTO EXACTLY)
// ------------------------------------------------------------
private func pbAlgorithm(from s: String?) -> PbAlgorithm {
    guard let x = s?.uppercased() else { return .algUnspecified }

    switch x {
    case "ED25519":       return .ed25519
    case "ES256":         return .es256
    case "ML-DSA-87":     return .mlDsa87
    case "ML_KEM_1024", "ML-KEM-1024":
                          return .mlKem1024
    case "SECP256K1":     return .secp256K1
    default:              return .algUnspecified
    }
}

private func pbAlgorithmToString(_ a: PbAlgorithm) -> String {
    switch a {
    case .ed25519:     return "Ed25519"
    case .es256:       return "ES256"
    case .mlDsa87:     return "ML-DSA-87"
    case .mlKem1024:   return "ML-KEM-1024"
    case .secp256K1:   return "secp256k1"
    default:           return ""
    }
}

private func pbKeyType(from s: String) -> PbKeyType {
    switch s {
    case "Multikey":         return .multikey
    case "P256Key2024":      return .p256Key2024
    case "MLDSA87Key2024":   return .mldsa87Key2024
    case "MLKEM1024Key2024": return .mlkem1024Key2024
    default:                 return .unspecified
    }
}

private func pbKeyTypeToString(_ t: PbKeyType) -> String {
    switch t {
    case .multikey:         return "Multikey"
    case .p256Key2024:      return "P256Key2024"
    case .mldsa87Key2024:   return "MLDSA87Key2024"
    case .mlkem1024Key2024: return "MLKEM1024Key2024"
    default:                return ""
    }
}

private func pbDVType(from s: String) -> PbDVType {
    switch s {
    case "DnsTxtVerification":        return .dnsTxt
    case "HttpsWellKnownVerification":return .httpsWellKnown
    default:                          return .dvtUnspecified
    }
}

private func pbDVTypeToString(_ t: PbDVType) -> String {
    switch t {
    case .dnsTxt:        return "DnsTxtVerification"
    case .httpsWellKnown:return "HttpsWellKnownVerification"
    default:             return ""
    }
}

// ------------------------------------------------------------
// BASE64URL HELPERS
// ------------------------------------------------------------
private func b64urlDecode(_ s: String) -> Data {
    let padded =
        s.replacingOccurrences(of: "-", with: "+")
         .replacingOccurrences(of: "_", with: "/")

    let pad = padded.count % 4
    let paddedFinal = padded + String(repeating: "=", count: pad == 0 ? 0 : 4 - pad)

    return Data(base64Encoded: paddedFinal) ?? Data()
}

private func b64urlEncode(_ d: Data) -> String {
    return d.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

// ------------------------------------------------------------
// 1. Swift DIDDocument → Protobuf
// ------------------------------------------------------------

/// Convert your Swift DIDDocument model into protobuf.
func didDocumentToProto(_ doc: DIDDocument) throws -> PbDIDDocument {
    var pb = PbDIDDocument()

    pb.id = doc.id
    pb.controller = doc.controller
    pb.ctx = doc.context
    pb.also = doc.alsoKnownAs
    pb.biometric = doc.biometricProtected ?? false
    pb.hardware = doc.hardwareBound ?? false
    pb.deviceModel = doc.deviceModel ?? ""

    pb.seq = UInt64(doc.sequence)
    pb.prev = doc.prev ?? ""
    pb.core = doc.currentCore

    pb.coreCbor = b64urlDecode(doc.coreCbor)

    pb.keyHistory = doc.keyHistory

    // verificationMethod
    pb.vm = doc.verificationMethod.map { vm in
        var pout = PbVMKey()
        pout.id = vm.id
        pout.controller = vm.controller
        pout.type = pbKeyType(from: vm.type)
        pout.alg = pbAlgorithm(from: vm.algorithm.rawValue)
        pout.pk = vm.publicKeyMultibase
        return pout
    }

    pb.authn = doc.authentication
    pb.assert = doc.assertionMethod
    pb.inv = doc.capabilityInvocation
    pb.ka = doc.keyAgreement

    // services
    pb.svc = doc.service.map { svc in
        var s = PbService()
        s.id = svc.id
        s.type = svc.type
        s.version = svc.version ?? ""
        switch svc.serviceEndpoint {
        case .uri(let u):
            s.endpoint = Data(u.utf8)
        case .map(let m):
            if let d = try? JSONEncoder().encode(m) {
                s.endpoint = d
            }
        }
        return s
    }

    // policy
    var pol = PbUpdatePolicy()
    pol.allowed = doc.updatePolicy.allowedVerificationMethods
    pb.policy = pol

    // attestations
    pb.att = doc.attestations.compactMap { a in
        var pa = PbAttestation()
        pa.alg = pbAlgorithm(from: a.alg)
        pa.vm = a.vm
        pa.sig = b64urlDecode(a.sig)
        return pa
    }

    // proof
    var p = PbProof()
    p.id = doc.proof.id ?? ""
    p.type = doc.proof.type
    p.cryptosuite = doc.proof.cryptosuite ?? ""
    p.purpose = doc.proof.proofPurpose
    p.vm = doc.proof.verificationMethod ?? ""
    p.created = doc.proof.created ?? ""
    p.jws = doc.proof.jws ?? ""
    pb.proof = p

    // domainVerification (if using)
    // pb.dv = ...

    return pb
}

// ------------------------------------------------------------
// 2. JSON → Protobuf (matches Go exactly)
// ------------------------------------------------------------

struct AnyJSON: Codable {}

struct DIDJSON: Codable {
    let context: [String]?
    let id: String
    let controller: String
    let alsoKnownAs: [String]?
    let biometricProtected: Bool?
    let hardwareBound: Bool?
    let deviceModel: String?

    let sequence: UInt64?
    let prev: String?
    let currentCore: String?
    let coreCbor: String?
    let keyHistory: [String]?

    struct VM: Codable {
        let id: String
        let controller: String
        let type: String
        let algorithm: String?
        let publicKeyMultibase: String
    }
    let verificationMethod: [VM]?

    let authentication: [String]?
    let assertionMethod: [String]?
    let capabilityInvocation: [String]?
    let keyAgreement: [String]?

    struct SVC: Codable {
        let id: String
        let type: String
        let version: String?
        let serviceEndpoint: AnyJSON?
    }
    let service: [SVC]?

    struct POL: Codable {
        let allowedVerificationMethods: [String]?
    }
    let updatePolicy: POL?

    struct ATT: Codable {
        let alg: String
        let vm: String
        let sig: String
    }
    let attestations: [ATT]?

    struct PR: Codable {
        let id: String?
        let type: String
        let cryptosuite: String?
        let proofPurpose: String
        let verificationMethod: String?
        let created: String?
        let jws: String?
    }
    let proof: PR?

    struct DV: Codable {
        let type: String
        let domain: String
        let method: String
        let proof: AnyJSON?
        let proofUrl: String?
        let verifiedAt: String?
    }
    let domainVerification: [DV]?

    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case id, controller, alsoKnownAs, biometricProtected, hardwareBound, deviceModel
        case sequence, prev, currentCore, coreCbor, keyHistory
        case verificationMethod, authentication, assertionMethod, capabilityInvocation
        case keyAgreement, service, updatePolicy, attestations, proof, domainVerification
    }
}

func jsonToProto(_ data: Data) throws -> PbDIDDocument {
    let dec = JSONDecoder()
    let j = try dec.decode(DIDJSON.self, from: data)

    var pb = PbDIDDocument()

    pb.id = j.id
    pb.controller = j.controller
    pb.ctx = j.context ?? []
    pb.also = j.alsoKnownAs ?? []
    pb.biometric = j.biometricProtected ?? false
    pb.hardware = j.hardwareBound ?? false
    pb.deviceModel = j.deviceModel ?? ""

    pb.seq = j.sequence ?? 0
    pb.prev = j.prev ?? ""
    pb.core = j.currentCore ?? ""

    if let c = j.coreCbor, let d = Data(base64Encoded: c) {
        pb.coreCbor = d
    }

    pb.keyHistory = j.keyHistory ?? []

    if let vms = j.verificationMethod {
        pb.vm = vms.map { v in
            var m = PbVMKey()
            m.id = v.id
            m.controller = v.controller
            m.type = pbKeyType(from: v.type)
            if let a = v.algorithm {
                m.alg = pbAlgorithm(from: a)
            }
            m.pk = v.publicKeyMultibase
            return m
        }
    }

    pb.authn = j.authentication ?? []
    pb.assert = j.assertionMethod ?? []
    pb.inv = j.capabilityInvocation ?? []
    pb.ka = j.keyAgreement ?? []

    if let svcs = j.service {
        pb.svc = svcs.map { s in
            var ps = PbService()
            ps.id = s.id
            ps.type = s.type
            ps.version = s.version ?? ""
            if let ep = s.serviceEndpoint,
               let d = try? JSONEncoder().encode(ep) {
                ps.endpoint = d
            }
            return ps
        }
    }

    if let pol = j.updatePolicy {
        var up = PbUpdatePolicy()
        up.allowed = pol.allowedVerificationMethods ?? []
        pb.policy = up
    }

    if let atts = j.attestations {
        pb.att = atts.map { a in
            var pa = PbAttestation()
            pa.alg = pbAlgorithm(from: a.alg)
            pa.vm = a.vm
            pa.sig = b64urlDecode(a.sig)
            return pa
        }
    }

    if let p = j.proof {
        var pp = PbProof()
        pp.id = p.id ?? ""
        pp.type = p.type
        pp.cryptosuite = p.cryptosuite ?? ""
        pp.purpose = p.proofPurpose
        pp.vm = p.verificationMethod ?? ""
        pp.created = p.created ?? ""
        pp.jws = p.jws ?? ""
        pb.proof = pp
    }

    if let dvs = j.domainVerification {
        pb.dv = dvs.map { dv in
            var p = PbDomainVerification()
            p.t = pbDVType(from: dv.type)
            p.domain = dv.domain
            p.method = dv.method
            if let pr = dv.proof,
               let d = try? JSONEncoder().encode(pr) {
                p.proof = d
            }
            p.proofURL = dv.proofUrl ?? ""
            p.verifiedAt = dv.verifiedAt ?? ""
            return p
        }
    }

    return pb
}

// ------------------------------------------------------------
// 3. Protobuf → JSON (matches Go/TS output shape)
// ------------------------------------------------------------

func protoToJSON(_ pb: PbDIDDocument) throws -> Data {
    var out: [String: Any] = [:]
    
    out["@context"] = pb.ctx
    out["id"] = pb.id
    out["controller"] = pb.controller
    out["alsoKnownAs"] = pb.also
    out["biometricProtected"] = pb.biometric
    out["hardwareBound"] = pb.hardware
    out["deviceModel"] = pb.deviceModel
    
    out["sequence"] = pb.seq
    out["prev"] = pb.prev
    out["currentCore"] = pb.core
    out["keyHistory"] = pb.keyHistory
    
    out["coreCbor"] = b64urlEncode(Data(pb.coreCbor))
        
    out["verificationMethod"] = pb.vm.map { vm in
        var d: [String: Any] = [
            "id": vm.id,
            "controller": vm.controller,
            "type": pbKeyTypeToString(vm.type),
            "publicKeyMultibase": vm.pk
        ]
        if vm.alg != .algUnspecified {
            d["algorithm"] = pbAlgorithmToString(vm.alg)
        }
        return d
    }
    
    out["authentication"] = pb.authn
    out["assertionMethod"] = pb.assert
    out["capabilityInvocation"] = pb.inv
    out["keyAgreement"] = pb.ka
    
    let decoder = JSONDecoder()
    out["service"] = pb.svc.map { s in
        var ep: Any = NSNull()
        if !s.endpoint.isEmpty,
           let o = try? decoder.decode(AnyJSON.self, from: s.endpoint) {
            ep = o
        }
        return [
            "id": s.id,
            "type": s.type,
            "version": s.version,
            "serviceEndpoint": ep
        ]
    }
    
    if pb.hasPolicy {
        out["updatePolicy"] = [
            "allowedVerificationMethods": pb.policy.allowed
        ]
    }
    
    out["attestations"] = pb.att.map { a in
        [
            "alg": pbAlgorithmToString(a.alg),
            "vm": a.vm,
            "sig": b64urlEncode(Data(a.sig))
        ]
    }
    
    if pb.hasProof {
        out["proof"] = [
            "id": pb.proof.id,
            "type": pb.proof.type,
            "cryptosuite": pb.proof.cryptosuite,
            "proofPurpose": pb.proof.purpose,
            "verificationMethod": pb.proof.vm,
            "created": pb.proof.created,
            "jws": pb.proof.jws
        ]
    }
    
    if !pb.dv.isEmpty {
        out["domainVerification"] = pb.dv.map { dv in
            var proof: Any = NSNull()
            if !dv.proof.isEmpty,
               let p = try? JSONSerialization.jsonObject(with: dv.proof) {
                proof = p
            }
            return [
                "type": pbDVTypeToString(dv.t),
                "domain": dv.domain,
                "method": dv.method,
                "proof": proof,
                "proofUrl": dv.proofURL,
                "verifiedAt": dv.verifiedAt
            ]
        }
    }
    
    return try JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted, .sortedKeys])
    
}
