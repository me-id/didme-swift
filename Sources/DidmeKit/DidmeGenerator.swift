//
//  DidmeGenerator.swift
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

public enum DIDGenerator {

    public struct Input {
        public var stableDid: String
        public var keyMaterial: DIDKeyMaterial
        public var previousKeyHistory: [String]
        public var deviceModel: String?
        public var alsoKnownAs: [String]
        public var services: [Service]

        public init(
            stableDid: String,
            keyMaterial: DIDKeyMaterial,
            previousKeyHistory: [String] = [],
            deviceModel: String? = nil,
            alsoKnownAs: [String] = [],
            services: [Service] = []
        ) {
            self.stableDid = stableDid
            self.keyMaterial = keyMaterial
            self.previousKeyHistory = previousKeyHistory
            self.deviceModel = deviceModel
            self.alsoKnownAs = alsoKnownAs
            self.services = services
        }
    }
    
    public struct Output {
        public var document: DIDDocument
        public var core: DIDCore.CoreEnvelope
    }

    /// Creates a new DID document and its core envelope from the given input.
    public static func create(input: Input) throws -> Output {

        print("create: start")

        let did = "did:me:\(input.stableDid)"
        print("create: after did")
        let km = input.keyMaterial


        // ----------------------------------------------------
        // 1. Build multikey encodings
        // ----------------------------------------------------

        print("create: building multikeys")

        let edMultikey = DIDMultikey.ed25519(input.keyMaterial.ed25519Pub)
        print("create: after ed25519")

        let p256Multikey = DIDMultikey.p256(input.keyMaterial.p256Pub)
        print("create: after p256")

        let root87Multikey = DIDMultikey.mldsa87(input.keyMaterial.mldsa87RootPub)
        print("create: after root87")

        let auth87Multikey = DIDMultikey.mldsa87(input.keyMaterial.mldsa87AuthPub)
        print("create: after auth87")

        let mlkemMultikey = DIDMultikey.mlkem1024(input.keyMaterial.mlkem1024Pub)
        print("create: after mlkem1024")

        let x25519Multikey = DIDMultikey.x25519(input.keyMaterial.x25519Pub)
        print("create: after x25519")

        let btcMultikey  = input.keyMaterial.btcSecp256k1Pub.map { DIDMultikey.secp256k1($0) }
        print("create: after btc")

        let ethMultikey  = input.keyMaterial.ethSecp256k1Pub.map { DIDMultikey.secp256k1($0) }
        print("create: after eth")

        let solMultikey  = input.keyMaterial.solEd25519Pub.map { DIDMultikey.solanaEd25519($0) }
        print("create: after sol")

        let avaxMultikey = input.keyMaterial.avaxSecp256k1Pub.map { DIDMultikey.secp256k1($0) }
        print("create: after avax")

        print("create: finished multikeys")

        // ----------------------------------------------------
        // 2. Core object used for content addressing (minimal VM set)
        // ----------------------------------------------------

        var coreVMs: [[String: Any]] = [
            [
                "id": "#mldsa87-root",
                "type": "MLDSA87Key2024",
                "algorithm": "ML-DSA-87",
                "publicKeyMultibase": root87Multikey
            ],
            [
                "id": "#mlkem1024",
                "type": "MLKEM1024Key2024",
                "algorithm": "ML-KEM-1024",
                "publicKeyMultibase": mlkemMultikey
            ],
            [
                "id": "#ed25519",
                "type": "Multikey",
                "algorithm": "Ed25519",
                "publicKeyMultibase": edMultikey
            ],
            [
                "id": "#p256",
                "type": "P256Key2024",
                "algorithm": "ES256",
                "publicKeyMultibase": p256Multikey
            ],
            [
                "id": "#mldsa87-auth",
                "type": "MLDSA87Key2024",
                "algorithm": "ML-DSA-87",
                "publicKeyMultibase": auth87Multikey
            ],
            [
                "id": "#x25519",
                "type": "Multikey",
                "algorithm": "X25519",
                "publicKeyMultibase": x25519Multikey
            ]
        ]
        
        if let btc = btcMultikey {
            coreVMs.append([
                "id": "#btc-secp256k1",
                "type": "Multikey",
                "algorithm": "secp256k1",
                "publicKeyMultibase": btc
            ])
        }
        if let eth = ethMultikey {
            coreVMs.append([
                "id": "#eth-secp256k1",
                "type": "Multikey",
                "algorithm": "secp256k1",
                "publicKeyMultibase": eth
            ])
        }
        if let sol = solMultikey {
            coreVMs.append([
                "id": "#sol-ed25519",
                "type": "Multikey",
                "algorithm": "Ed25519",
                "publicKeyMultibase": sol
            ])
        }
        if let avax = avaxMultikey {
            coreVMs.append([
                "id": "#avax-secp256k1",
                "type": "Multikey",
                "algorithm": "secp256k1",
                "publicKeyMultibase": avax
            ])
        }
        
        // sequence / prev per spec:
        let sequence = input.previousKeyHistory.count + 1
        let prevCid = input.previousKeyHistory.last
        
        var coreObject: [String: Any] = [
            "id": did,
            "sequence": sequence,
            "controller": did,
            "controllerKeys": coreVMs,
            "authenticationKeys": ["#ed25519", "#mldsa87-auth"],
            "assertionKeys": ["#ed25519", "#mldsa87-auth", "#p256"],
            "keyAgreementKeys": ["#x25519", "#mlkem1024"],
            "services": [],
            "updatePolicy": [
                "allowedVerificationMethods": ["#mldsa87-root"]
            ],
            "updatedAt": ISO8601DateFormatter().string(from: Date())
        ]
        
        if let prevCid = prevCid {
            coreObject["prev"] = prevCid
        }
        
        // ----------------------------------------------------
        // Encode CoreEnvelope (CBOR + CID)
        // ----------------------------------------------------

        let coreEnvelope = try DIDCore.encodeCore(coreObject)

        // ----------------------------------------------------
        // 3. Key history with new core CID appended
        // ----------------------------------------------------

        // keyHistory: MUST contain only prior CIDs (no currentCore)
        let keyHistory = input.previousKeyHistory

        // ----------------------------------------------------
        // 4. Build full verificationMethod array for DID Document
        // ----------------------------------------------------

        var verificationMethods: [VerificationMethod] = [
            VerificationMethod(
                id: "#mldsa87-root",
                controller: did,
                type: "MLDSA87Key2024",
                algorithm: .mldsa87,
                publicKeyMultibase: root87Multikey
            ),
            VerificationMethod(
                id: "#ed25519",
                controller: did,
                type: "Multikey",
                algorithm: .ed25519,
                publicKeyMultibase: edMultikey
            ),
            VerificationMethod(
                id: "#p256",
                controller: did,
                type: "P256Key2024",
                algorithm: .es256,
                publicKeyMultibase: p256Multikey
            ),
            VerificationMethod(
                id: "#mldsa87-auth",
                controller: did,
                type: "MLDSA87Key2024",
                algorithm: .mldsa87,
                publicKeyMultibase: auth87Multikey
            ),
            VerificationMethod(
                id: "#mlkem1024",
                controller: did,
                type: "MLKEM1024Key2024",
                algorithm: .mlkem1024,
                publicKeyMultibase: mlkemMultikey
            ),
            VerificationMethod(
                id: "#x25519",
                controller: did,
                type: "Multikey",
                algorithm: .x25519,
                publicKeyMultibase: x25519Multikey
            )
        ]
        
        if let btc = btcMultikey {
            verificationMethods.append(
                VerificationMethod(
                    id: "#btc-secp256k1",
                    controller: did,
                    type: "Multikey",
                    algorithm: .secp256k1,
                    publicKeyMultibase: btc
                )
            )
        }
        if let eth = ethMultikey {
            verificationMethods.append(
                VerificationMethod(
                    id: "#eth-secp256k1",
                    controller: did,
                    type: "Multikey",
                    algorithm: .secp256k1,
                    publicKeyMultibase: eth
                )
            )
        }
        if let sol = solMultikey {
            verificationMethods.append(
                VerificationMethod(
                    id: "#sol-ed25519",
                    controller: did,
                    type: "Multikey",
                    algorithm: .ed25519,
                    publicKeyMultibase: sol
                )
            )
        }
        if let avax = avaxMultikey {
            verificationMethods.append(
                VerificationMethod(
                    id: "#avax-secp256k1",
                    controller: did,
                    type: "Multikey",
                    algorithm: .secp256k1,
                    publicKeyMultibase: avax
                )
            )
        }
        
        // ----------------------------------------------------
        // 5. Relationship arrays
        // ----------------------------------------------------

        let authentication = [
            "#ed25519",
            "#mldsa87-auth"
        ]

        let assertionMethod = [
            "#ed25519",
            "#mldsa87-auth",
            "#p256"
        ]

        let capabilityInvocation = [
            "#mldsa87-root"
        ]

        let keyAgreement = [
            "#x25519",
            "#mlkem1024"
        ]
        // ----------------------------------------------------
        // 6. Services — injected by caller (app-level)
        // ----------------------------------------------------
        let services = input.services

        // ----------------------------------------------------
        // 7. Update policy
        // ----------------------------------------------------

        let updatePolicy = UpdatePolicy(allowedVerificationMethods: ["#mldsa87-root"])

        // ----------------------------------------------------
        // 8. Attestation + Proof
        // ----------------------------------------------------

        // Attestation: ML-DSA-87 root key over core CBOR (signed content)
        let attestationEntry = try DIDAttestation.create(
            coreCBOR: coreEnvelope.cbor,
            secretKeyPEM: input.keyMaterial.mldsa87RootSecretPEM,
            vmFragment: "#mldsa87-root"
        )

        // Proof: P-256 Data Integrity Proof over core CID
        let proofEntry = try DIDProof.createP256Proof(
            coreCid: coreEnvelope.cid,
            p256PrivateKey: input.keyMaterial.p256SoftwarePrivateKey,
            secKey: input.keyMaterial.p256SecureEnclavePrivateKey,
            vmFragment: "#p256"
        )

        // ----------------------------------------------------
        // 9. DID Document assembly
        // ----------------------------------------------------

        let document = DIDDocument(
            context: [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
                "https://w3id.org/security/suites/secp256r1-2019/v1",
                "https://me-id.org/ns/did-me/v1"
            ],
            id: did,
            controller: did,
            alsoKnownAs: input.alsoKnownAs,
            sequence: sequence,
            prev: prevCid,
            hardwareBound: km.isHardwareBacked,
            biometricProtected: km.isBiometricProtected,
            userVerificationMethod: km.userVerificationMethod,
            deviceModel: input.deviceModel,
            coreCbor: DIDEncodingUtils.base64urlEncode(coreEnvelope.cbor),
            currentCore: coreEnvelope.cid,
            keyHistory: keyHistory,
            verificationMethod: verificationMethods,
            authentication: authentication,
            assertionMethod: assertionMethod,
            capabilityInvocation: capabilityInvocation,
            keyAgreement: keyAgreement,
            service: services,
            updatePolicy: updatePolicy,
            attestations: [attestationEntry],
            proof: proofEntry
        )

        return Output(document: document, core: coreEnvelope)
    }


    
}
