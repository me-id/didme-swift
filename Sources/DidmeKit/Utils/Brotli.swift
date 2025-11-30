//
//  Brotli.swift
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
import Compression

public enum DIDBrotli {

    /// Brotli compress (level 11, same as Go/Node: BROTLI_MAX_QUALITY)
    public static func compress(_ data: Data) throws -> Data {
        if #available(iOS 17.0, macOS 14.0, *) {
            return try compressNative(data)
        } else {
            return try compressFallback(data)
        }
    }

    /// Brotli decompress (fully compatible)
    public static func decompress(_ data: Data) throws -> Data {
        if #available(iOS 17.0, macOS 14.0, *) {
            return try decompressNative(data)
        } else {
            return try decompressFallback(data)
        }
    }
}

// ------------------------------------------------------------
// MARK: - Native (iOS 17+/macOS14+)
// ------------------------------------------------------------

@available(iOS 17.0, macOS 14.0, *)
public extension DIDBrotli {

    static func compressNative(_ data: Data) throws -> Data {
        let encoder = try Compression.Brotli.Encoder(mode: .generic, quality: 11)
        return try encoder.encode(data)
    }

    static func decompressNative(_ data: Data) throws -> Data {
        let decoder = try Compression.Brotli.Decoder()
        return try decoder.decode(data)
    }
}

// ------------------------------------------------------------
// MARK: - Fallback (portable pure-Swift Brotli)
// ------------------------------------------------------------

public extension DIDBrotli {

    static func compressFallback(_ data: Data) throws -> Data {
        // Fallback uses Apple's old low-level API
        return try performFallback(
            data,
            operation: COMPRESSION_STREAM_ENCODE,
            algorithm: COMPRESSION_BROTLI
        )
    }

    static func decompressFallback(_ data: Data) throws -> Data {
        return try performFallback(
            data,
            operation: COMPRESSION_STREAM_DECODE,
            algorithm: COMPRESSION_BROTLI
        )
    }

    static func performFallback(_ data: Data,
                                operation: compression_stream_operation,
                                algorithm: compression_algorithm) throws -> Data {

        var stream = compression_stream()
        var status = compression_stream_init(&stream, operation, algorithm)
        guard status != COMPRESSION_STATUS_ERROR else {
            throw NSError(domain: "brotli", code: -1)
        }
        defer { compression_stream_destroy(&stream) }

        let dstSize = 64 * 1024
        let dstBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: dstSize)
        defer { dstBuffer.deallocate() }

        return data.withUnsafeBytes { (srcPtr: UnsafeRawBufferPointer) -> Data in
            var out = Data()

            stream.src_ptr = srcPtr.bindMemory(to: UInt8.self).baseAddress!
            stream.src_size = srcPtr.count
            stream.dst_ptr = dstBuffer
            stream.dst_size = dstSize

            repeat {
                status = compression_stream_process(&stream, 0)

                switch status {
                case COMPRESSION_STATUS_OK,
                     COMPRESSION_STATUS_END:
                    let written = dstSize - stream.dst_size
                    out.append(dstBuffer, count: written)
                    stream.dst_ptr = dstBuffer
                    stream.dst_size = dstSize
                default:
                    return Data()
                }

            } while status == COMPRESSION_STATUS_OK

            return out
        }
    }
}

