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
import SwiftBrotli

public enum BrotliError: Error {
    case compressFailed(Error)
    case decompressFailed(Error)
}

public enum DIDBrotli {

    public static func compress(_ data: Data) throws -> Data {
        let brotli = Brotli()
        let result = brotli.compress(data)

        switch result {
        case .success(let compressed):
            return compressed
        case .failure(let error):
            throw BrotliError.compressFailed(error)
        }
    }

    public static func decompress(_ data: Data) throws -> Data {
        let brotli = Brotli()
        let result = brotli.decompress(data)

        switch result {
        case .success(let decompressed):
            return decompressed
        case .failure(let error):
            throw BrotliError.decompressFailed(error)
        }
    }
}
