//
//  ProtoBrotli.swift
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

// MARK: - High-level helpers

/// DIDDocument (Swift) -> Protobuf binary (uncompressed)
public func encodeDidToProtoBinary(_ doc: DIDDocument) throws -> Data {
    let pb = try didDocumentToProto(doc)
    return try pb.serializedData()
}

/// DIDDocument (Swift) -> Brotli-compressed Protobuf binary
public func encodeDidToBrotliProto(_ doc: DIDDocument) throws -> Data {
    let bin = try encodeDidToProtoBinary(doc)
    return try DIDBrotli.compress(bin)
}

/// Brotli-compressed Protobuf -> DIDDocument (Swift model)
public func decodeBrotliProtoToDidDocument(_ data: Data) throws -> DIDDocument {
    // 1. Decompress Brotli
    let decompressed = try DIDBrotli.decompress(data)

    // 2. Parse protobuf (new API)
    let pb = try PbDIDDocument(serializedBytes: decompressed)

    // 3. Convert proto -> JSON Data
    let jsonData = try protoToJSON(pb)

    // 4. Decode JSON -> DIDDocument (your Swift model)
    let decoder = JSONDecoder()
    return try decoder.decode(DIDDocument.self, from: jsonData)
}

/// Brotli-compressed Protobuf -> JSON Data (matches Go/TS output)
public func decodeBrotliProtoToJSON(_ data: Data) throws -> Data {
    let decompressed = try DIDBrotli.decompress(data)
    let pb = try PbDIDDocument(serializedBytes: decompressed)
    return try protoToJSON(pb)
}
