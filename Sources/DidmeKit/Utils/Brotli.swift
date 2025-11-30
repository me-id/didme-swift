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

    public static func compress(_ data: Data) throws -> Data {
        try perform(operation: COMPRESSION_STREAM_ENCODE,
                    algorithm: COMPRESSION_BROTLI,
                    data: data)
    }

    public static func decompress(_ data: Data) throws -> Data {
        try perform(operation: COMPRESSION_STREAM_DECODE,
                    algorithm: COMPRESSION_BROTLI,
                    data: data)
    }

    private static func perform(operation: compression_stream_operation,
                                algorithm: compression_algorithm,
                                data: Data) throws -> Data {

        var stream = compression_stream()
        var status = compression_stream_init(&stream, operation, algorithm)
        guard status != COMPRESSION_STATUS_ERROR else {
            throw NSError(domain: "brotli", code: -1)
        }
        defer { compression_stream_destroy(&stream) }

        let dstBufferSize = 64 * 1024
        let dstBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: dstBufferSize)
        defer { dstBuffer.deallocate() }

        return data.withUnsafeBytes { srcRawBuffer in
            var result = Data()
            stream.src_ptr  = srcRawBuffer.bindMemory(to: UInt8.self).baseAddress!
            stream.src_size = srcRawBuffer.count
            stream.dst_ptr  = dstBuffer
            stream.dst_size = dstBufferSize

            repeat {
                status = compression_stream_process(&stream, 0)

                let written = dstBufferSize - stream.dst_size
                if written > 0 {
                    result.append(dstBuffer, count: written)
                }

                stream.dst_ptr = dstBuffer
                stream.dst_size = dstBufferSize
            } while status == COMPRESSION_STATUS_OK

            return result
        }
    }
}
