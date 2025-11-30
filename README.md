# DidmeKit


**DidmeKit** is a Swift library providing a complete toolkit for building,
signing, verifying, and managing **Decentralized Identifiers (DIDs)** using the
`did:me` DID method.

DidmeKit includes:

- DID Document generation  
- Canonicalization (JCS)  
- DID Core (DAG-CBOR + CIDv1)  
- Multibase / Multicodec key encoding  
- ML-DSA-87 attestations  
- P-256 (ES256) Data Integrity proofs  
- DID Document verification  
- DID rotation logic  

DidmeKit is platform-agnostic and suitable for iOS, macOS, and
server-side Swift.

---

## ✨ Features

### 🔐 DID Generation
- Ed25519  
- X25519  
- P-256 (software or Secure Enclave)  
- ML-DSA-87 (post-quantum signatures)  
- ML-DSA-54 (optional)  
- ML-KEM-1024 (post-quantum encryption)  
- Built-in DID type rules (identity, persona, group, org)

### 📄 DID Document Construction
- Full DID Document assembly (verification methods, services, relationships)
- DID Core envelope generation (DAG-CBOR + CIDv1)
- Multikey via multicodec + multibase base58btc
- JCS Canonical JSON output

### 🔏 Signatures & Proofs
- ML-DSA-87 root attestation over core CBOR
- P-256 / ES256 Data Integrity Proof (compact JWS)
- Secure Enclave signing when available

### 🔍 Verification
- DID Document structure validation
- ML-DSA-87 signature verification
- P-256 DID update proof verification
- CID continuity & keyHistory validation
- Round-trip JCS canonicalization testing

### 🗃 DID Storage
- Stores canonical JSON + metadata (note/tags)
- Does **not** store private keys


---

## 🛠 Installation

Add DidmeKit to your project using Swift Package Manager.

### Xcode

1. File → Add Packages...
2. Enter the repository URL:  
   ```
   https://github.com/<your-org>/DidmeKit.git
   ```
3. Add the library to your app or framework target.

### Package.swift

```swift
dependencies: [
    .package(url: "https://github.com/<your-org>/DidmeKit.git", from: "0.1.0")
],
targets: [
    .target(name: "MyApp", dependencies: ["DidmeKit"])
]
```

---

## 🧱 Architecture Overview

DidmeKit is organized into several clean, independent modules:

```
Sources/DidmeKit/
    DIDKeyGenerator.swift
    DIDGenerator.swift
    DIDCore.swift
    DIDJCS.swift
    DIDMultikey.swift
    DIDCryptoUtils.swift
    DIDEncodingUtils.swift
    DIDDocument.swift
    DIDProof.swift
    DIDAttestation.swift
    DIDService.swift
    DIDRotationService.swift
    DIDPublisher.swift
    DIDVerifier.swift
    DIDStore.swift
```

The module is designed to be:

- cryptographically correct  
- deterministic  
- self-contained  
- testable  
- modular  

---

## 🚀 Example Usage

### Create a DID

```swift
import DidmeKit

let keyMaterial = try DIDKeyGenerator.generateKeyMaterialForCurrentEnvironment()
let (stableHex, shortId, _) = DIDHelpers.makeStableDidAndShortId()

let input = DIDGenerator.Input(
    stableDid: stableHex,
    shortId: shortId,
    keyMaterial: keyMaterial
)

let output = try DIDGenerator.create(input: input)
let did = output.document.id
```

### Canonicalize DID Document

```swift
let jcs = try DIDJCS.canonicalData(from: output.document)
```

### Verify DID Document

```swift
let result = DIDVerifier.verify(document: output.document, jcsData: jcs)
print(result.isValid)  // true
```

### Store DID Document

```swift
try DIDStore.shared.saveDocument(
    id: did,
    json: jcs,
    note: "Main identity",
    tags: ["primary"],
    extra: nil,
    createdAt: Date().timeIntervalSince1970,
    updatedAt: Date().timeIntervalSince1970
)
```

---

## 🧪 Testing

DidmeKit is fully tested using XCTest.

Tests live in:

```
Tests/DidmeKitTests/
```

Including:

- DIDMultikeyTests
- DIDCoreTests
- DIDJCSTests
- DIDProofTests
- DIDVerifierTests

Run:

```
swift test
```

---

## 📚 Roadmap

- [ ] Add BBS+ verification  
- [ ] Add JSON-LD / RDF canonicalization mode  
- [ ] Add DID Resolver for did:me  
- [ ] Key rotation policies per DID type  
- [ ] Expand ML-DSA-family multicodecs  
- [ ] Swift Concurrency refinements across services  
- [ ] Publish to Swift Package Index  

---

## 📄 License

[Apache 2 License](LICENSE)

---

Want integration docs or a full architecture diagram?  
Open an issue or discussion!
