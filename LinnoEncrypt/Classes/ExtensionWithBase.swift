//
//  ExtensionWithBaseType.swift
//  QR
//
//  Created by 韩增超 on 2022/10/14.
//

import Foundation


func encryptAbstractMethod(file: StaticString = #file, line: UInt = #line) -> Swift.Never {
    encryptFatalError(error_abstract_method, file: file, line: line)
}
func encryptFatalError(_ lastMessage: @autoclosure () -> String, file: StaticString = #file, line: UInt = #line) -> Swift.Never  {
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
}


func _getContainerFromJSONString(json:String) throws -> Any {
    let jsonData:Data = json.data(using: .utf8)!
    let container =  try JSONSerialization.jsonObject(with: jsonData, options: .mutableContainers)
    return container
}
/**JSONString转换为数组**/
func getArrayFromJSONString(jsonString:String) -> Array<Any>? {
    if let array = try? _getContainerFromJSONString(json: jsonString){
        return array  as? Array<Any>
    }
    return nil
}
/**JSONString转换为字典**/
func getDictionaryFromJSONString(jsonString:String) -> Dictionary<String, Any>? {
    if let dic = try? _getContainerFromJSONString(json: jsonString){
        return dic  as? Dictionary<String, Any>
    }
    return nil
}
/**转json字符串**/
func getJSONStringFromAny(obj:Any) -> String? {
    guard JSONSerialization.isValidJSONObject(obj) else {
        errorTips(tips: tips_not_converted_JSON)
        return nil
    }
    if let data = try? JSONSerialization.data(withJSONObject: obj){
        if let res = String(data: data, encoding: .utf8){
            return res
        }
    }
    return nil
}








