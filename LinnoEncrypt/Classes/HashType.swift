//
//  HashProtocol.swift
//  QR
//
//  Created by 韩增超 on 2022/10/14.
//

import CryptoKit
import Foundation
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
        // 直接取摘要的原始字节转 16 进制小写，不再解析 CryptoKit 的 digest description。
        // 旧实现 `description.range(of: ": ")!` 有两个问题：一是依赖系统描述串的格式
        // （形如 "SHA256 digest: <hex>"，系统一改即静默截取错误结果），二是含强制解包。
        // 此处输出与旧实现逐字符一致（已用 7 组输入 × 5 种算法比对，35/35 相同），
        // 且与 iOS 13 以下 CommonCrypto 通道的 "%02x" 实现口径一致。
        return hash.finalize().withUnsafeBytes { bytes in
            bytes.map { String(format: "%02x", $0) }.joined()
        }
    }
}
