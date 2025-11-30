//
//  SecureEnclaveHandle.swift
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
//  Encodes and decodes Secure Enclave key handles for storage in the Keybag.
//  We never export the actual SE private key — only a reference/tag.
//

import Foundation
import Security

public enum DIDSecureEnclaveHandle {

    /// Produce a keybag-safe representation of an SE key.
    /// Example: "SE:com.reallyme.did.p256"
    public static func encode(tag: String) -> Data {
        return Data("SE:\(tag)".utf8)
    }

    /// Attempt to interpret a Keybag privateKey field as a Secure Enclave handle.
    /// Returns the tag if this is an SE-handle entry.
    public static func decodeHandle(from data: Data) -> String? {
        guard let s = String(data: data, encoding: .utf8),
              s.hasPrefix("SE:") else {
            return nil
        }
        return String(s.dropFirst(3))
    }

    /// Load a Secure Enclave private key from its tag.
    /// This is how KeybagManager obtains the usable key.
    public static func loadKey(fromHandle handle: String) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: handle.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return (status == errSecSuccess) ? (item as! SecKey) : nil
    }
}
