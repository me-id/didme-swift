//
//  CryptoUtils.swift
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
//  Low-level crypto utilities used across DidmeKit.
//  Includes PEM/DER helpers, hashing helpers, and general crypto formatting.
//  NOT for key generation (see DIDKeyGenerator).
//

import Foundation
import CryptoKit

public enum DIDCryptoUtils {

    // MARK: - PEM ⇄ DER Conversion

    /// Strips PEM header/footer lines and decodes the Base64 payload into DER bytes.
    public static func pemToDer(_ pem: String) -> Data {
        // Remove common PEM headers/footers and whitespace, then base64-decode.
        let cleaned = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        return Data(base64Encoded: cleaned) ?? Data()
    }

    /// Convert DER to PEM with given header/footer type.
    public static func derToPem(_ der: Data, type: String) -> String {
        let b64 = der.base64EncodedString(options: [.lineLength64Characters])
        return """
        -----BEGIN \(type)-----
        \(b64)
        -----END \(type)-----
        """
    }

    // MARK: - Hashing

    public static func sha256(_ data: Data) -> Data {
        return Data(SHA256.hash(data: data))
    }

    public static func sha512(_ data: Data) -> Data {
        return Data(SHA512.hash(data: data))
    }

    public static func sha3_256(_ data: Data) -> Data {
        return Data(SHA3_256.hash(data: data))
    }

    // MARK: - Equality & Constant-Time Compare

    /// Constant-time comparison for cryptographic equality checks.
    public static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[i] ^ b[i]
        }
        return result == 0
    }

    // MARK: - Randomness

    public static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess)
        return Data(bytes)
    }
}
