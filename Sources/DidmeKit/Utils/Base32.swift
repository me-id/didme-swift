//
//  Base32.swift
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

public enum Base32 {

    // Alphabet: A–Z + 2–7
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    // Lowercase + uppercase decode table
    private static let decodeTable: [UInt8: UInt8] = {
        var table = [UInt8: UInt8]()
        for (i, char) in alphabet.enumerated() {
            table[char] = UInt8(i)

            // Compute lowercase mapping
            let scalar = UnicodeScalar(char)
            let lowerString = scalar.properties.lowercaseMapping

            if let lowerByte = lowerString.utf8.first {
                table[lowerByte] = UInt8(i)
            }
        }
        return table
    }()

    // ============================================================
    // MARK: Encode (Data → Base32 string)
    // ============================================================

    public static func encode(_ data: Data) -> String {
        guard !data.isEmpty else { return "" }

        var result = [UInt8]()
        result.reserveCapacity((data.count * 8 + 4) / 5)

        var buffer: UInt = 0
        var bitsLeft = 0

        for byte in data {
            buffer = (buffer << 8) | UInt(byte)
            bitsLeft += 8

            while bitsLeft >= 5 {
                let index = Int((buffer >> UInt(bitsLeft - 5)) & 0x1F)
                guard index < alphabet.count else { return "" }
                result.append(alphabet[index])
                bitsLeft -= 5
            }
        }

        // Remaining bits
        if bitsLeft > 0 {
            let index = Int((buffer << UInt(5 - bitsLeft)) & 0x1F)
            guard index < alphabet.count else { return "" }
            result.append(alphabet[index])
        }

        return String(bytes: result, encoding: .utf8) ?? ""
    }

    // ============================================================
    // MARK: Decode (Base32 string → Data)
    // ============================================================

    public static func decode(_ string: String) -> Data? {
        guard !string.isEmpty else { return Data() }

        var buffer: UInt = 0
        var bitsLeft = 0
        var output = [UInt8]()

        for char in string.utf8 {
            guard let value = decodeTable[char] else {
                return nil        // invalid character
            }

            buffer = (buffer << 5) | UInt(value)
            bitsLeft += 5

            if bitsLeft >= 8 {
                bitsLeft -= 8
                let byte = UInt8((buffer >> UInt(bitsLeft)) & 0xFF)
                output.append(byte)
            }
        }

        return Data(output)
    }
}
