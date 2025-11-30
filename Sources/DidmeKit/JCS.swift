//
//  JCS.swift
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
//  JSON Canonicalization Scheme (JCS) for DID Documents.
//  Produces deterministic UTF-8 JSON output suitable for hashing,
//  attestation, signing, publishing, or comparing DID Documents.
//
//  Supports:
//    • String
//    • Number (minimal decimal form)
//    • Bool
//    • Null
//    • Arrays
//    • Maps (sorted lexicographically by key)
//    • Encodable (via round-trip through JSONSerialization)
//

import Foundation

public enum DIDJCS {

    /// Canonicalizes any JSON-compatible object (dictionary, array, string, number…).
    public static func canonicalData(from jsonObject: Any) throws -> Data {
        var out = Data()
        try appendCanonicalJSON(into: &out, value: jsonObject)
        return out
    }

    /// Canonicalizes an Encodable value.
    /// Encodes with JSONEncoder → parses to JSON tree → canonicalizes.
    public static func canonicalData<T: Encodable>(from encodable: T) throws -> Data {
        let encoded = try JSONEncoder().encode(encodable)
        let obj = try JSONSerialization.jsonObject(with: encoded, options: [])
        return try canonicalData(from: obj)
    }

    /// Convenience wrapper returning UTF-8 string.
    public static func canonicalString(from jsonObject: Any) throws -> String {
        let data = try canonicalData(from: jsonObject)
        return String(data: data, encoding: .utf8)!
    }

    public static func canonicalString<T: Encodable>(from encodable: T) throws -> String {
        let data = try canonicalData(from: encodable)
        return String(data: data, encoding: .utf8)!
    }
}

// MARK: - Internal JCS Encoder

private func appendCanonicalJSON(into out: inout Data, value: Any) throws {
    switch value {

    case let s as String:
        try out.append(jsonEscapedString(s))

    case let n as NSNumber:
        if CFGetTypeID(n) == CFBooleanGetTypeID() {
            out.append(n.boolValue ? Data("true".utf8) : Data("false".utf8))
        } else {
            // Minimal JSON number syntax
            out.append(Data(n.stringValue.utf8))
        }

    case _ as NSNull:
        out.append(Data("null".utf8))

    case let b as Bool:
        out.append(b ? Data("true".utf8) : Data("false".utf8))

    case let a as [Any]:
        out.append(0x5B) // '['
        for i in 0..<a.count {
            if i > 0 { out.append(0x2C) } // ','
            try appendCanonicalJSON(into: &out, value: a[i])
        }
        out.append(0x5D) // ']'

    case let m as [String: Any]:
        out.append(0x7B) // '{'
        let keys = m.keys.sorted()
        for (i, k) in keys.enumerated() {
            if i > 0 { out.append(0x2C) } // ','
            try out.append(jsonEscapedString(k))
            out.append(0x3A) // ':'
            try appendCanonicalJSON(into: &out, value: m[k]!)
        }
        out.append(0x7D) // '}'

    default:
        // Normalize unknown values through JSONSerialization and try again.
        let data = try JSONSerialization.data(withJSONObject: value, options: [])
        let obj = try JSONSerialization.jsonObject(with: data, options: [])
        try appendCanonicalJSON(into: &out, value: obj)
    }
}

private func jsonEscapedString(_ s: String) throws -> Data {
    // JSONSerialization escapes strings correctly.
    // Encoding ["s"] yields a one-element array JSON string → extract the element.
    let encoded = try JSONSerialization.data(withJSONObject: [s], options: [])
    guard let str = String(data: encoded, encoding: .utf8) else {
        return Data("\"\(s)\"".utf8)
    }

    // The format is ["…escaped…"].
    // Extract inner quoted string.
    guard
        let first = str.firstIndex(of: "\""),
        let last = str.lastIndex(of: "\""),
        last > first
    else {
        return Data("\"\(s)\"".utf8)
    }

    let content = str[str.index(after: first)..<last]
    return Data("\"\(content)\"".utf8)
}
