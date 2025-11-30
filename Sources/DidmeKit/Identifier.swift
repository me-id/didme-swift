//
//  IdentifierGenerator.swift
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
//  Generates stable did:me identifiers using:
//  - 16 bytes entropy (128 bits)
//  - 8→5 bit conversion
//  - Bech32 encoding with HRP "me"
//

import Foundation
import CryptoKit

public struct DIDIdentifier {
    public let string: String   // "me1xxxx..."
    public let entropy: Data    // 16 random bytes
}

public enum DIDIdentifierGenerator {

    // ------------------------------------------------------------
    // MARK: - Public API
    // ------------------------------------------------------------

    /// Generates a stable did:me identifier (entropy only, no internal checksum).
    public static func generate() -> DIDIdentifier {

        // 1. 16 bytes entropy (128 bits)
        let entropy = randomBytes(16)

        // 2. Convert 8-bit bytes → 5-bit groups
        guard let fiveBit = entropy.convertBits(fromBits: 8, toBits: 5, pad: true) else {
            fatalError("convertBits(8→5) failed; should never happen.")
        }

        // 3. Encode via Bech32 with HRP "me"
        let encoded = Bech32.encode(hrp: "me", data: fiveBit)

        // 4. Only the Bech32 payload — caller prefixes "did:me:"
        return DIDIdentifier(string: encoded, entropy: entropy)
    }

    // ------------------------------------------------------------
    // MARK: - Random bytes
    // ------------------------------------------------------------

    private static func randomBytes(_ count: Int) -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        precondition(status == errSecSuccess, "Failed to generate random bytes")
        return data
    }
}

// ------------------------------------------------------------
// MARK: - Bit Conversion (8 ↔︎ 5) for Bech32
// ------------------------------------------------------------

public extension Data {
    /// Converts between bit group sizes (e.g., 8→5 and 5→8 for Bech32).
    func convertBits(fromBits: Int, toBits: Int, pad: Bool) -> Data? {
        var acc = 0
        var bits = 0
        var result = Data()
        let maxv = (1 << toBits) - 1

        for value in self {
            acc = (acc << fromBits) | Int(value)
            bits += fromBits
            while bits >= toBits {
                bits -= toBits
                result.append(UInt8((acc >> bits) & maxv))
            }
        }

        if pad && bits > 0 {
            result.append(UInt8((acc << (toBits - bits)) & maxv))
        } else if bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0 {
            return nil
        }

        return result
    }
}
