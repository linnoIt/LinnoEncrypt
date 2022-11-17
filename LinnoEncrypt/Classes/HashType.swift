//
//  HashProtocol.swift
//  QR
//
//  Created by 韩增超 on 2022/10/14.
//

import CryptoKit
/**散列协议*/
protocol HashType {
    // 需要散列的数据转换为原始信息message的UInt8数组
    var message: [UInt8] { set get }
    /** 追加1和0的计算 */
    func prepare(_ len: Int) -> [UInt8]
    /** 散列方法*/
    func hashString(sourceString: String) -> String
}

/** 散列协议扩展*/
extension HashType {
    
    var message: [UInt8] {
       get { return [] }
       set { /* default set do nothing */ }
    }
    /** message  追加1和0 填充信息的长度*/
    func prepare(_ len: Int) -> [UInt8] {
        var tmpMessage = message
        // append "1" bit 到message中 0x80 = 10000000(二进制)
        tmpMessage.append(0x80)

       // 获取原始信息数组的长度
        var msgLength = tmpMessage.count
        var counter = 0
        // 留 64 bit长度添加message原始长度的bit数据
        while msgLength % len != (len - 8) {
            counter += 1
            msgLength += 1
        }
        // append "0" bit 到message中
        tmpMessage += [UInt8](repeating: 0, count: counter)
        return tmpMessage
    }
    
    
    @available(iOS 13.0, *)
    /** iOS  13.0 以后提供hash方法，MD5 、sha1、sha256、sha384、sha512*/
    func _hash<T:HashFunction>(hashData: Data ,hashClass: T) -> String {
        var hash =  hashClass
        hash.update(data:hashData)
        let digestString:String = hash.finalize().description
        let deRange = digestString.range(of: ": ")
        return String(digestString.suffix(from: deRange!.upperBound))
    }
}
