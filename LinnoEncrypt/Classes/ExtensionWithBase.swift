//
//  ExtensionWithBaseType.swift
//  QR
//
//  Created by 韩增超 on 2022/10/14.
//

import Foundation

/**
 抽象方法兜底。
 Debug 构建下 assertionFailure 立即中断，暴露"子类未实现该抽象方法"；
 Release 构建下断言被编译器消除，仅打印错误并返回空 Data，避免线上直接崩溃。
 */
@discardableResult
func encryptAbstractMethod(file: StaticString = #file, line: UInt = #line) -> Data {
    let message = "\(error_abstract_method)(\(file):\(line))"
    errorTips(tips: message)
    assertionFailure(message)
    return Data()
}
func encryptFatalError(_ lastMessage: @autoclosure () -> String, file: StaticString = #file, line: UInt = #line) -> Swift.Never {
    fatalError(lastMessage(), file: file, line: line)
}

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
extension String {
    var base64Encoded:String {
        let data = self.data(using: .utf8) ?? Data()
        return data.base64EncodedString(options: .lineLength64Characters)
    }
    var base64Dcoded:String {
        let data = Data(base64Encoded: self, options: .ignoreUnknownCharacters) ?? Data()
        return String(data: data, encoding: .utf8) ?? error_base64_Decoding
    }
    /** 字符串转16进制data*/
    func hexadecimal() -> Data? {
        var data = Data(capacity: self.count / 2)
        guard let regex = try? NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive) else {
            return nil
        }
        regex.enumerateMatches(in: self, range: NSMakeRange(0, utf16.count)) { match, flags, stop in
            guard let match = match else { return }
            let byteString = (self as NSString).substring(with: match.range)
            guard let num = UInt8(byteString, radix: 16) else { return }
            var byte = num
            data.append(&byte, count: 1)
        }
        guard data.count > 0 else { return nil }
        return data
    }
}

extension Data {
    /** Data 转16进制字符串方法 */
    func hexadecimal() -> String {
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
}

/** 获取json转换后的容器 */
func _getContainerFromJSONString(json: String) throws -> Any {
    guard let jsonData = json.data(using: .utf8) else {
        throw NSError(domain: "LinnoEncrypt", code: -1,
                      userInfo: [NSLocalizedDescriptionKey: tips_data_type_error])
    }
    return try JSONSerialization.jsonObject(with: jsonData, options: .mutableContainers)
}
/**JSONString转换为数组**/
func getArrayFromJSONString(jsonString: String) -> Array<Any>? {
    if let array = try? _getContainerFromJSONString(json: jsonString) {
        return array as? Array<Any>
    }
    return nil
}
/**JSONString转换为字典**/
func getDictionaryFromJSONString(jsonString: String) -> Dictionary<String, Any>? {
    if let dic = try? _getContainerFromJSONString(json: jsonString) {
        return dic  as? Dictionary<String, Any>
    }
    return nil
}
/**转json字符串**/
func getJSONStringFromAny(obj: Any) -> String? {
    guard JSONSerialization.isValidJSONObject(obj) else {
        errorTips(tips: tips_not_converted_JSON)
        return nil
    }
    if let data = try? JSONSerialization.data(withJSONObject: obj) {
        if let res = String(data: data, encoding: .utf8) {
            return res
        }
    }
    return nil
}
/**分割数组**/
func dealListToNumSubList<T>(list: [T], num:Int) -> [[T]] {
    let count = list.count / num
    let mod = list.count % num
    var targetList: [[T]] = []

    for i in 0 ..< count {
        let firstIndex = i * num
        let subList = Array(list[firstIndex ... firstIndex + num - 1])
        targetList.append(subList)
    }
    //有余数, 加上最后剩下的数据
    if mod > 0 {
        let lastList = Array(list[ list.count - mod ..< list.count])
        targetList.append(lastList)
    }
    return targetList
}







