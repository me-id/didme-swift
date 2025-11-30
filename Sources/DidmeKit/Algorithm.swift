//  Algorithm.swift
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

public enum DIDAlgorithm: String, Codable {
    case ed25519       = "Ed25519"
    case x25519        = "X25519"
    case es256         = "ES256"
    case secp256k1     = "secp256k1"
    case mldsa87       = "ML-DSA-87"
    case mlkem1024     = "ML-KEM-1024"
}


public enum MulticodecKeyType: UInt16, Codable {
    case ed25519Pub      = 0xed
    case x25519Pub       = 0xec
    case p256Pub         = 0x1200
    case secp256k1Pub    = 0xe7
    case mldsa87Pub      = 0x1212 
    case mlkem1024Pub    = 0x120d
}
