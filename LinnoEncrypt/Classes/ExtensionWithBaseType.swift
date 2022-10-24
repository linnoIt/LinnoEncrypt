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
/** string 扩展 base64 编解码属性*/
extension String{
    var base64Encoded:String{
        let data = self.data(using: .utf8) ?? Data()
        return data.base64EncodedString(options: .lineLength64Characters)
    }
    var base64Dcoded:String{
        let data = Data(base64Encoded: self, options: .ignoreUnknownCharacters) ?? Data()
        return String(data: data, encoding: .utf8) ?? error_base64_Decoding
    }
}

extension Data {
    /// Data扩展 16进制字符串属性
    var hexadecimal:String{
        let bytes = [UInt8](self)
        var hexString = ""
        for index in 0..<self.count {
            let newHex = String(format: "%x", bytes[index]&0xff)
            if newHex.count == 1 {
                hexString = String(format: "%@0%@", hexString, newHex)
            } else {
                hexString += newHex
            }
        }
        return hexString
    }
    /**
        - Returns: A value that is hexadecimal ,format is [UInt8].
     */
    func bytes() -> [UInt8] {
        let string = self.hexadecimal
        var start = string.startIndex
        return stride(from: 0, to: string.count, by: 2).compactMap { _ in
            let end = string.index(after: start)
            defer {start = string.index(after: end)}
            return UInt8(string[start...end], radix: 16)
        }
    }
}

