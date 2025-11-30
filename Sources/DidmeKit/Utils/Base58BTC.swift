//
//  Base58BTC.swift
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

public enum Base58BTC {

    // ============================================================
    // MARK: - Alphabet + Decode Map
    // ============================================================

    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)

    private static let decodeMap: [UInt8: Int] = {
        var map = [UInt8: Int]()
        for (i, char) in alphabet.enumerated() {
            map[char] = i
        }
        return map
    }()

    // ============================================================
    // MARK: - ENCODE
    // ============================================================

    public static func encode(_ data: Data) -> String {
        guard !data.isEmpty else { return "" }

        var bytes = [UInt8](data)

        // Count leading zeros → "1"
        var zeros = 0
        for b in bytes {
            if b == 0 { zeros += 1 } else { break }
        }

        var num = bytes.map { BigInt(Int($0)) }
        var result: [Int] = []

        while !(num.count == 1 && num[0].isZero) {
            var remainder = 0
            var next = [BigInt]()

            for n in num {
                let acc = remainder * 256 + n.intValue
                let digit = acc / 58
                remainder = acc % 58

                // skip *leading* zero digits, but don't drop all digits
                if !next.isEmpty || digit != 0 {
                    next.append(BigInt(digit))
                }
            }

            result.append(remainder)

            // if quotient is zero, represent it as [0] so loop terminates
            if next.isEmpty {
                num = [BigInt(0)]
            } else {
                num = next
            }
        }

        var out = String(repeating: "1", count: zeros)
        for r in result.reversed() {
            guard r < alphabet.count else { return "" }
            out.append(Character(UnicodeScalar(Int(alphabet[r]))!))
        }
        return out
    }

    // ============================================================
    // MARK: - DECODE
    // ============================================================

    public static func decode(_ string: String) -> Data? {
        guard !string.isEmpty else { return Data() }

        let bytes = Array(string.utf8)

        // Leading "1" → zero bytes
        var zeros = 0
        for b in bytes {
            if b == 49 { zeros += 1 } else { break }   // ASCII "1"
        }

        var num = [BigInt(0)]

        for c in bytes {
            guard let value = decodeMap[c] else {
                return nil        // invalid character
            }

            var carry = value

            for i in 0..<num.count {
                let acc = num[i].intValue * 58 + carry
                num[i] = BigInt(acc % 256)
                carry = acc / 256
            }

            while carry > 0 {
                num.append(BigInt(carry % 256))
                carry /= 256
            }
        }

        // Convert BigInt → bytes (little-endian → big-endian)
        // Convert reversed() view into a *mutable array*
        var payload = Array(num.map { UInt8($0.intValue) }.reversed())

        // Strip leading zeros introduced by base58 math
        while payload.first == 0 {
            payload.removeFirst()
        }

        // Restore zero-prefix derived from leading "1"
        let zeroBytes = Array(repeating: UInt8(0), count: zeros)
        return Data(zeroBytes + payload)
    }

    // ============================================================
    // MARK: - BigInt tiny wrapper
    // ============================================================

    private struct BigInt {
        var intValue: Int
        var isZero: Bool { intValue == 0 }
        init(_ v: Int) { intValue = v }
    }
}
