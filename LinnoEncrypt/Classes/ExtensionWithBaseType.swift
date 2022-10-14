//
//  ExtensionWithBaseType.swift
//  QR
//
//  Created by 韩增超 on 2022/10/14.
//

import Foundation


extension Int {
    // 在小端上：将数字以256进制实现数组，数组从右到左实现
    // eg: num = 255 -> [0, 0, 0, 0, 0, 0, 0, 255]
    //     num = 256 -> [0, 0, 0, 0, 0, 0, 1, 0]
    func bytes(_ totalBytes: Int = MemoryLayout<Int>.size) -> [UInt8] {
        return arrayOfBytes(self, length: totalBytes)
    }

}
func arrayOfBytes<T>(_ value: T, length: Int? = nil) -> [UInt8] {
    let totalBytes = length ?? (MemoryLayout<T>.size * 8)

    let valuePointer = UnsafeMutablePointer<T>.allocate(capacity: 1)
    valuePointer.pointee = value

    let bytes = valuePointer.withMemoryRebound(to: UInt8.self, capacity: totalBytes) { (bytesPointer) -> [UInt8] in
        var bytes = [UInt8](repeating: 0, count: totalBytes)
        for j in 0..<min(MemoryLayout<T>.size, totalBytes) {
            bytes[totalBytes - 1 - j] = (bytesPointer + j).pointee
        }
        return bytes
    }

    valuePointer.deinitialize(count: 1)
    valuePointer.deallocate()

    return bytes
}
