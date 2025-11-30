//
//  Multikey.swift
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
//  Multicodec + Multibase encoders for did:me.
//
//  These functions encode raw or DER-encoded public keys into the multibase
//  format used inside verificationMethod.publicKeyMultibase.
//
//  For classical keys → Base58BTC (“z…”)
//  For PQ keys (Dilithium / Kyber) → Base64URL (“u…”) to avoid extremely slow Base58
//
//  All functions return a String beginning with a correct multibase prefix,
//  or "z?…" / "u?…" on failure.
//

import Foundation

public enum DIDMultikey {

    // ============================================================
    // MARK: - Public API: Multikey Encoders
    // ============================================================

    /// Ed25519 signing public key (raw 32 bytes)
    public static func ed25519(_ raw: Data) -> String {
        safe( multibase58(multicodec: 0xED, key: raw), fallback: "z?ed25519" )
    }

    /// X25519 key agreement public key (raw 32 bytes)
    public static func x25519(_ raw: Data) -> String {
        safe( multibase58(multicodec: 0xEC, key: raw), fallback: "z?x25519" )
    }

    /// P-256 verification public key
    /// Multicodec 0x1200 = p256-pub (SEC1 **compressed** 33 bytes)
    public static func p256(_ raw: Data) -> String {
        // Accept either uncompressed 65-byte 0x04||X||Y or already-compressed 33-byte.
        let key: Data
        if raw.count == 65 && raw.first == 0x04 {
            let x = raw[1...32]
            let yLast = raw[64]
            let prefix: UInt8 = (yLast & 1) == 0 ? 0x02 : 0x03
            key = Data([prefix]) + x
        } else {
            key = raw
        }
        guard key.count == 33, key.first == 0x02 || key.first == 0x03 else {
            return safe(nil, fallback: "z?p256")
        }
        return safe( multibase58(multicodec: 0x1200, key: key), fallback: "z?p256" )
    }

    // ------------------------------------------------------------
    // MARK: PQ KEYS (Dilithium, Kyber)
    // ------------------------------------------------------------

    /// ML-DSA-87 public key (RAW bytes) → base64url ("u...")
    /// Multicodec 0x1207 = mldsa-pub
    public static func mldsa87(_ raw: Data) -> String {
        safe( multibaseB64(multicodec: 0x1212, key: raw), fallback: "u?mldsa87" )
    }


    /// ML-KEM-1024 public key (RAW bytes) → base64url ("u...")
    /// Multicodec 0x120D = mlkem-1024-pub
    public static func mlkem1024(_ raw: Data) -> String {
        safe( multibaseB64(multicodec: 0x120D, key: raw), fallback: "u?mlkem1024" )
    }

    // ------------------------------------------------------------
    // secp256k1 (compressed)
    // ------------------------------------------------------------
    public static func secp256k1(_ raw: Data) -> String {
        safe( multibase58(multicodec: 0xE7, key: raw), fallback: "z?secp256k1" )
    }

    /// Solana Ed25519
    public static func solanaEd25519(_ raw: Data) -> String {
        safe( multibase58(multicodec: 0xED, key: raw), fallback: "z?sol" )
    }

    // ============================================================
    // MARK: - BASE58 (for classical keys)
    // ============================================================

    private static func multibase58(multicodec: Int, key: Data) -> String? {
        guard !key.isEmpty else { return nil }
        guard multicodec > 0 && multicodec < 0xFFFFFF else { return nil }

        print("🔵 DIDMultikey: Base58 encode start — codec=\(String(multicodec, radix:16)), keyBytes=\(key.count)")

        let prefix = uvarint(multicodec)
        let combined = Data(prefix) + key

        let encoded = DIDMultibase.encodeBase58btc(combined)

        guard encoded.starts(with: "z") else {
            print("🔴 DIDMultikey: Base58 result invalid (missing z-prefix)")
            return nil
        }

        print("🟢 DIDMultikey: Base58 encode OK → \(encoded.prefix(20))…")

        return encoded
    }

    // ============================================================
    // MARK: - BASE64URL (for PQ keys)
    // ============================================================

    private static func multibaseB64(multicodec: Int, key: Data) -> String? {
        guard !key.isEmpty else { return nil }
        guard multicodec > 0 && multicodec < 0xFFFFFF else { return nil }

        print("🔵 DIDMultikey: Base64url encode PQ key — codec=\(String(multicodec, radix:16)), bytes=\(key.count)")

        let prefix = uvarint(multicodec)
        let combined = Data(prefix) + key

        let encoded = DIDMultibase.encodeBase64url(combined)

        guard encoded.starts(with: "u") else {
            print("🔴 DIDMultikey: Base64url result invalid (missing u-prefix)")
            return nil
        }

        print("🟢 DIDMultikey: Base64url PQ encode OK → \(encoded.prefix(20))…")

        return encoded
    }

    // ============================================================
    // MARK: - Safe API wrapper (never returns nil)
    // ============================================================

    private static func safe(_ v: String?, fallback: String) -> String {
        if let v { return v }
        print("⚠️ DIDMultikey fallback → \(fallback)")
        return fallback
    }
}

//
// MARK: - Internal helpers (uvarint)
//

/// Unsigned varint encoding for multicodec identifiers.
private func uvarint(_ v: Int) -> [UInt8] {
    var x = v
    var out = [UInt8]()
    var guardCounter = 0

    while true {
        guard guardCounter < 5 else {
            print("⚠️ uvarint overflow → truncated")
            break
        }
        guardCounter += 1

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

//
// MARK: - Minimal fallback Base58 (not used in production)
//

private let b58Alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)

private func base58btcEncode(_ bytes: Data) -> String {
    print("⚠️ WARNING — fallback base58btcEncode() was used. This should never happen.")
    var x = [UInt8](bytes)
    var zeros = 0
    for b in x { if b == 0 { zeros += 1 } else { break } }

    var num = x.map { BigInt(Int($0)) }
    var res = [Int]()
    var limit = 0

    while !(num.count == 1 && num[0].isZero) {
        guard limit < 4096 else { break }
        limit += 1

        var rem = 0
        var next = [BigInt]()
        for n in num {
            let acc = rem * 256 + n.intValue
            let digit = acc / 58
            rem = acc % 58
            if !(next.isEmpty && digit == 0) { next.append(BigInt(digit)) }
        }
        res.append(rem)
        num = next
    }

    var out = String(repeating: "1", count: zeros)
    for r in res.reversed() { out.append(Character(UnicodeScalar(b58Alphabet[r]))) }
    return out
}

private struct BigInt {
    var intValue: Int
    var isZero: Bool { intValue == 0 }
    init(_ v: Int) { intValue = v }
}
