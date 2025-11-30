//
//  EncodingUtils.swift
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
//  Encoding helpers for DIDKit:
//    • Base64URL encoding/decoding
//    • gzip compression + base64url
//    • Raw gzip/gunzip helpers
//
//  These functions are designed to be deterministic and safe for DID-related tasks.
//

import Foundation
import Compression

public enum DIDEncodingUtils {

    // ============================================================
    // MARK: - Base64URL (RFC 4648 §5)
    // ============================================================

    /// Encodes raw data into Base64URL format (no padding).
    public static func base64urlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decodes a Base64URL-encoded string (with or without padding).
    public static func base64urlDecode(_ s: String) -> Data? {
        var str = s
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Restore padding if necessary.
        while str.count % 4 != 0 {
            str.append("=")
        }

        return Data(base64Encoded: str)
    }

    // ============================================================
    // MARK: - Gzip (zlib wrapper)
    // ============================================================

    /// Compresses data using gzip-compatible zlib format.
    public static func gzip(_ data: Data) throws -> Data {
        guard !data.isEmpty else { return Data() }
        return try compress(data, algorithm: COMPRESSION_ZLIB)
    }

    /// Decompresses gzip-compatible zlib data.
    public static func gunzip(_ data: Data) throws -> Data {
        guard !data.isEmpty else { return Data() }
        return try decompress(data, algorithm: COMPRESSION_ZLIB)
    }

    // ============================================================
    // MARK: - Gzip + Base64URL Convenience
    // ============================================================

    /// gzip → base64url pipeline
    public static func gzipBase64url(_ data: Data) throws -> String {
        return base64urlEncode(try gzip(data))
    }

    // ============================================================
    // MARK: - Compression Helpers
    // ============================================================

    private static func compress(
        _ data: Data,
        algorithm: compression_algorithm
    ) throws -> Data {

        return try data.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> Data in
            guard let srcPtr = src.baseAddress else { return Data() }

            // Allocate raw byte buffer (NOT a Data instance)
            let bufferSize = max(64_000, data.count * 2)
            var outBytes = [UInt8](repeating: 0, count: bufferSize)

            let written = compression_encode_buffer(
                &outBytes,
                bufferSize,
                srcPtr.assumingMemoryBound(to: UInt8.self),
                data.count,
                nil,
                algorithm
            )

            if written == 0 {
                throw EncodingError.compressionFailed
            }

            // Build Data AFTER the unsafe access
            return Data(outBytes[0..<written])
        }
    }

    private static func decompress(
        _ data: Data,
        algorithm: compression_algorithm
    ) throws -> Data {

        var bufferSize = max(data.count * 4, 16_384)
        let maxBuffer = 10_000_000

        while bufferSize <= maxBuffer {

            var outBytes = [UInt8](repeating: 0, count: bufferSize)

            let written = outBytes.withUnsafeMutableBytes { dst -> Int in
                guard let dstPtr = dst.baseAddress else { return 0 }

                return data.withUnsafeBytes { src -> Int in
                    guard let srcPtr = src.baseAddress else { return 0 }

                    return compression_decode_buffer(
                        dstPtr.assumingMemoryBound(to: UInt8.self),
                        bufferSize,
                        srcPtr.assumingMemoryBound(to: UInt8.self),
                        data.count,
                        nil,
                        algorithm
                    )
                }
            }

            if written > 0 {
                return Data(outBytes[0..<written])
            }

            bufferSize *= 2
        }

        throw EncodingError.decompressionFailed
    }

    // ============================================================
    // MARK: - Errors
    // ============================================================

    public enum EncodingError: Error {
        case compressionFailed
        case decompressionFailed
    }
}
