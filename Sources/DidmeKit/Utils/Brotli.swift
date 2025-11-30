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

public enum BrotliError: Error {
    case streamInit
    case streamProcess
    case invalidData
}

public enum DIDBrotli {

    public static func compress(_ data: Data) throws -> Data {
        try process(data,
                    operation: COMPRESSION_STREAM_ENCODE,
                    algorithm: COMPRESSION_BROTLI)
    }

    public static func decompress(_ data: Data) throws -> Data {
        try process(data,
                    operation: COMPRESSION_STREAM_DECODE,
                    algorithm: COMPRESSION_BROTLI)
    }

    private static func process(
        _ data: Data,
        operation: compression_stream_operation,
        algorithm: compression_algorithm
    ) throws -> Data {

        if data.isEmpty { return Data() }

        // Explicit struct initialization
        var stream = compression_stream()

        var status = compression_stream_init(&stream, operation, algorithm)
        guard status != COMPRESSION_STATUS_ERROR else {
            throw BrotliError.streamInit
        }
        defer { compression_stream_destroy(&stream) }

        let bufferSize = 64 * 1024
        var output = Data()

        return try data.withUnsafeBytes { (srcPtr: UnsafeRawBufferPointer) -> Data in

            guard let base = srcPtr.bindMemory(to: UInt8.self).baseAddress else {
                throw BrotliError.invalidData
            }

            stream.src_ptr  = base
            stream.src_size = data.count

            let dstBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
            defer { dstBuffer.deallocate() }

            stream.dst_ptr = dstBuffer
            stream.dst_size = bufferSize

            func drain() {
                let written = bufferSize - stream.dst_size
                if written > 0 {
                    output.append(dstBuffer, count: written)
                }
                stream.dst_ptr = dstBuffer
                stream.dst_size = bufferSize
            }

            repeat {
                status = compression_stream_process(&stream, 0)
                if status == COMPRESSION_STATUS_ERROR { throw BrotliError.streamProcess }
                drain()
            } while status == COMPRESSION_STATUS_OK

            repeat {
                status = compression_stream_process(&stream, COMPRESSION_STREAM_FINALIZE)
                if status == COMPRESSION_STATUS_ERROR { throw BrotliError.streamProcess }
                drain()
            } while status == COMPRESSION_STATUS_OK

            if status != COMPRESSION_STATUS_END {
                throw BrotliError.invalidData
            }

            return output
        }
    }
}
