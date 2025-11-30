//
//  Core.swift
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
//  Minimal DAG-CBOR + CIDv1 encoder used by did:me core envelopes.
//
//  This file provides the “content addressed” core representation:
//     • Deterministic DAG-CBOR encoding
//     • SHA-256 multihash
//     • CIDv1(dag-cbor) construction
//     • Multibase base32-lower encoding (“b…”)
//
//  The resulting `CoreEnvelope` is:
//       { cbor: <DAG-CBOR bytes>, cid: "b..." }
//
//  The DIDGenerator attaches:
//       • ML-DSA-87 root attestation over `cbor`
//       • P-256 DataIntegrityProof over `cid`
//
//  NOTE: This is intentionally minimalistic and only supports:
//        - String
//        - Bool
//        - Int
//        - Data
//        - [Any]
//        - [String: Any]
//
//        The ordering of map keys is canonical (UTF-8 lexicographic).
//

import Foundation
import CryptoKit

public enum DIDCore {

    // MARK: - CoreEnvelope

    /// The deterministically encoded core object and its content identifier.
    public struct CoreEnvelope {
        /// DAG-CBOR bytes of the core object.
        public let cbor: Data

        /// CIDv1 (dag-cbor) encoded using multibase base32-lower.
        /// Always begins with `"b"`.
        public let cid: String
    }

    // MARK: - Public API

    /// Deterministically encodes a JSON-like structure into DAG-CBOR and computes its CID.
    ///
    /// - Parameter core: A JSON-like structure
    ///   composed of: `[String: Any]`, `[Any]`, `String`, `Bool`, `Int`, `Data`.
    ///
    /// - Returns: A CoreEnvelope containing CBOR bytes and a CIDv1 (“b…”) string.
    public static func encodeCore(_ core: Any) throws -> CoreEnvelope {
        let cbor = try cborEncode(core)
        let cid = cidV1DagCBORBase32(cbor)
        return CoreEnvelope(cbor: cbor, cid: cid)
    }
}

// MARK: - Internal Errors

private enum CBORError: Error {
    case badType
}

// =====================================================================
// MARK: - DAG-CBOR Encoding (minimal, deterministic)
// =====================================================================

/// Encode a JSON-like object to CBOR.
private func cborEncode(_ v: Any) throws -> Data {
    var out = Data()
    try cborAppend(&out, v)
    return out
}

/// Append CBOR representation of a single object into a buffer.
private func cborAppend(_ out: inout Data, _ v: Any) throws {
    switch v {

    case let s as String:
        let bytes = Data(s.utf8)
        cborMajorLen(&out, major: 3, len: bytes.count)   // major type 3 = text
        out.append(bytes)

    case let a as [Any]:
        cborMajorLen(&out, major: 4, len: a.count)       // major type 4 = array
        for x in a { try cborAppend(&out, x) }

    case let m as [String: Any]:
        // DAG-CBOR canonical: keys sorted lexicographically by UTF-8 bytes
        let sorted = m.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
        cborMajorLen(&out, major: 5, len: sorted.count)  // major type 5 = map
        for key in sorted {
            try cborAppend(&out, key)
            try cborAppend(&out, m[key]!)
        }

    case let b as Data:
        cborMajorLen(&out, major: 2, len: b.count)       // major type 2 = bytes
        out.append(b)

    case let n as Int:
        if n >= 0 {
            cborMajorLen(&out, major: 0, len: n)         // unsigned int
        } else {
            cborMajorLen(&out, major: 1, len: -n - 1)    // negative int encoding
        }

    case let bool as Bool:
        out.append(bool ? 0xF5 : 0xF4)                   // CBOR true/false

    default:
        throw CBORError.badType
    }
}

/// Writes the CBOR "major type + length" prefix.
private func cborMajorLen(_ out: inout Data, major: UInt8, len: Int) {
    let prefix = major << 5

    switch len {
    case 0..<24:
        out.append(prefix | UInt8(len))

    case 24..<256:
        out.append(prefix | 24)
        out.append(UInt8(len))

    case 256..<65_536:
        out.append(prefix | 25)
        out.append(contentsOf: withUnsafeBytes(of: UInt16(len).bigEndian, Array.init))

    default:
        out.append(prefix | 26)
        out.append(contentsOf: withUnsafeBytes(of: UInt32(len).bigEndian, Array.init))
    }
}

// =====================================================================
// MARK: - Multihash(sha2-256) + CIDv1(dag-cbor) + base32-lower
// =====================================================================

/// Multihash(sha2-256) = varint(0x12) + varint(32) + SHA-256 digest
private func multihashSHA256(_ input: Data) -> Data {
    let digest = Data(SHA256.hash(data: input))
    var out = Data()
    out.append(contentsOf: uvarint(0x12))             // code for sha2-256
    out.append(contentsOf: uvarint(digest.count))     // length (32)
    out.append(digest)
    return out
}

/// Multicodec varint encoding
private func uvarint(_ v: Int) -> [UInt8] {
    var x = v
    var out: [UInt8] = []

    while true {
        var b = UInt8(x & 0x7F)
        x >>= 7
        if x == 0 {
            out.append(b)
            break
        }
        b |= 0x80
        out.append(b)
    }
    return out
}

/// Base32-lowercase encoding, no padding. Used by multibase "b".
private let b32Alphabet = Array("abcdefghijklmnopqrstuvwxyz234567".utf8)

private func base32LowerNoPad(_ data: Data) -> String {
    var out: [UInt8] = []
    out.reserveCapacity((data.count * 8 + 4) / 5)

    var buffer: UInt = 0
    var bits = 0

    for byte in data {
        buffer = (buffer << 8) | UInt(byte)
        bits += 8
        while bits >= 5 {
            bits -= 5
            let idx = Int((buffer >> bits) & 0x1F)
            out.append(b32Alphabet[idx])
        }
    }

    if bits > 0 {
        let idx = Int((buffer << (5 - bits)) & 0x1F)
        out.append(b32Alphabet[idx])
    }

    return String(bytes: out, encoding: .utf8)!
}

/// Build CIDv1(dag-cbor) then encode using multibase base32-lower.
private func cidV1DagCBORBase32(_ payload: Data) -> String {
    var cid = Data()
    cid.append(0x01)                        // CIDv1
    cid.append(contentsOf: uvarint(0x71))   // multicodec: dag-cbor
    cid.append(multihashSHA256(payload))    // SHA256 multihash

    // Prefix with multibase base32-lower: "b"
    return "b" + base32LowerNoPad(cid)
}
