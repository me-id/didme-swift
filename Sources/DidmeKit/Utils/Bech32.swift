//
//  Bech32.swift
//  CryptoKitPlus
//
//  Original implementation:
//  SwiftBTC
//  Created by Otto Suess on 22.08.18.
//  Copyright © 2018 Zap.
//
//  Modifications:
//  - Namespaced under `CryptoKitPlus`
//  - Added documentation and MARKs
//  - Integrated into modular Encoding subsystem
//
//  Modifications:
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

public enum Bech32 {

    // MARK: - Constants

    private static let alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private static let generator = [
        0x3b6a57b2,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3
    ]

    // MARK: - Human Readable Part Expansion

    private static func expandHumanReadablePart(_ hrp: String) -> Data {
        guard let bytes = hrp.data(using: .utf8) else { return Data() }

        var out = Data()
        for b in bytes { out.append(UInt8(b >> 5)) }
        out.append(0)
        for b in bytes { out.append(UInt8(b & 0x1F)) }

        return out
    }

    // MARK: - Polymod Checksum

    private static func polymod(values: Data) -> Int {
        var chk = 1
        for v in values {
            let top = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ Int(v)

            for (i, g) in generator.enumerated() where ((top >> i) & 1) != 0 {
                chk ^= g
            }
        }
        return chk
    }

    private static func verifyChecksum(hrp: String, data: Data) -> Bool {
        polymod(values: expandHumanReadablePart(hrp) + data) == 1
    }

    private static func createChecksum(hrp: String, data: Data) -> Data {
        let values = expandHumanReadablePart(hrp) + data + Data(repeating: 0, count: 6)
        let mod = polymod(values: values) ^ 1

        var out = Data()
        for i in 0..<6 {
            out.append(UInt8((mod >> (5 * (5 - i))) & 0x1F))
        }
        return out
    }

    // MARK: - Character Validation

    private static func hasValidCharacters(_ input: String) -> Bool {
        guard let bytes = input.data(using: .utf8) else { return false }

        var hasLower = false
        var hasUpper = false

        for c in bytes {
            let v = UInt32(c)
            if v < 33 || v > 126 { return false }
            if (97...122).contains(v) { hasLower = true }
            if (65...90).contains(v) { hasUpper = true }
        }

        return !(hasLower && hasUpper)
    }

    // MARK: - Decode

    public static func decode(_ bech32: String, limit: Bool = true) -> (hrp: String, data: Data)? {
        guard hasValidCharacters(bech32) else { return nil }

        let s = bech32.lowercased()

        guard let pos = s.lastIndex(of: "1") else { return nil }
        if pos == s.startIndex { return nil }
        if s.distance(from: pos, to: s.endIndex) < 7 { return nil }
        if limit && s.count > 90 { return nil }

        let hrp = String(s[..<pos])
        let dataPart = s[s.index(after: pos)...]

        var values = Data()
        for c in dataPart {
            guard let idx = alphabet.firstIndex(of: c) else { return nil }
            let dist = alphabet.distance(from: alphabet.startIndex, to: idx)
            values.append(UInt8(dist))
        }

        guard verifyChecksum(hrp: hrp, data: values) else { return nil }

        return (hrp, Data(values[..<(values.count - 6)]))
    }

    // MARK: - Encode Helpers

    private static func toChars(data: Data) -> String {
        data.map {
            let idx = alphabet.index(alphabet.startIndex, offsetBy: Int($0))
            return String(alphabet[idx])
        }.joined()
    }

    // MARK: - Encode

    public static func encode(hrp: String, data: Data) -> String {
        let checksum = createChecksum(hrp: hrp, data: data)
        let combined = data + checksum
        return hrp + "1" + toChars(data: combined)
    }
}
