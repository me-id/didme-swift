//
//  Helpers.swift
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
//  Helper utilities for DID creation:
//    • Stable DID seed generation
//    • Short ID generation ("i:xxxxxxx")
//    • Base64url helpers
//    • Randomness helpers
//

import Foundation
import CryptoKit

public enum DIDHelpers {

    // MARK: - Stable DID generation

    /// Generates a 16-byte stable DID seed and its hex encoding.
    /// This is the stable anchor for a DID of form "did:me:<hex>".
    public static func generateStableDidSeed() -> (hex: String, bytes: Data) {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(status == errSecSuccess)

        let data = Data(bytes)
        let hex = data.map { String(format: "%02x", $0) }.joined()
        return (hex, data)
    }

    // MARK: - Short ID (alias) generation

    /// Generates a deterministic short alias for "alsoKnownAs".
    /// e.g. input: random 16 bytes → "i:3f8a9b5cd"
    public static func makeShortId(from bytes: Data) -> String {
        let h = SHA256.hash(data: bytes)
        let hex = h.map { String(format: "%02x", $0) }.joined()
        return "i:" + hex.prefix(9)
    }

    // Convenience: generate both stable DID + short ID
    public static func makeStableDidAndShortId() -> (stableHex: String, shortId: String, seed: Data) {
        let (hex, seed) = generateStableDidSeed()
        let short = makeShortId(from: seed)
        return (hex, short, seed)
    }

    // MARK: - Base64URL encoding/decoding

    public static func base64urlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func base64urlDecode(_ s: String) -> Data? {
        var str = s
        str = str.replacingOccurrences(of: "-", with: "+")
        str = str.replacingOccurrences(of: "_", with: "/")
        while str.count % 4 != 0 { str += "=" }
        return Data(base64Encoded: str)
    }

    // MARK: - Randomness

    /// Convenience for generating arbitrary secure random bytes.
    public static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess)
        return Data(bytes)
    }
}
