//
//  Multibase.swift
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
//  Multibase encode/decode helpers for DIDKit.
//  Supports:
//     • base58btc  ("z...")
//     • base32     ("b...")
//     • base64url  ("u...")
//     • hex        ("f...")
//
//  Always returns *Data?* for decode. Invalid encodings return nil.
//

import Foundation

public enum DIDMultibase {

    // ============================================================
    // MARK: - Encode
    // ============================================================

    /// Multibase base58btc: prefix "z"
    public static func encodeBase58btc(_ data: Data) -> String {
        // Base58BTC.encode is provided in DIDKit
        return "z" + Base58BTC.encode(data)
    }

    /// Multibase base32: prefix "b"
    public static func encodeBase32(_ data: Data) -> String {
        return "b" + Base32.encode(data)
    }

    /// Multibase base64url: prefix "u" (no padding)
    public static func encodeBase64url(_ data: Data) -> String {
        let s = data
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "u" + s
    }

    /// Multibase hex: prefix "f"
    public static func encodeHex(_ data: Data) -> String {
        return "f" + data.map { String(format: "%02x", $0) }.joined()
    }

    // ============================================================
    // MARK: - Decode (any multibase)
    // ============================================================

    /// Decodes *any* multibase-prefixed string ("z", "u", "b", "f").
    /// Returns nil for malformed or unknown prefixes.
    public static func decode(_ s: String) -> Data? {
        guard let prefix = s.first else { return nil }
        let body = String(s.dropFirst())

        switch prefix {

        case "z":   // base58btc
            return Base58BTC.decode(body)

        case "u":   // base64url
            var str = body
                .replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
            while str.count % 4 != 0 { str.append("=") }
            return Data(base64Encoded: str)

        case "b":   // base32
            return Base32.decode(body)

        case "f":   // hex
            return Data(hexString: body)

        default:
            return nil
        }
    }
}

//
// MARK: - Hex decode helper
//

private extension Data {
    init?(hexString: String) {
        var bytes = [UInt8]()
        bytes.reserveCapacity(hexString.count / 2)

        var buffer: UInt8?
        for c in hexString {
            guard let v = c.hexDigitValue else { return nil }
            if let b = buffer {
                bytes.append(UInt8((b << 4) | UInt8(v)))
                buffer = nil
            } else {
                buffer = UInt8(v)
            }
        }

        // odd-length hex string → invalid
        if buffer != nil { return nil }

        self = Data(bytes)
    }
}
