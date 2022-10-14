//
//  HashProtocol.swift
//  QR
//
//  Created by 韩增超 on 2022/10/14.
//

import Foundation


/** 加密协议*/
protocol AsymmetricType {
    // 需要加密的数据转换为原始信息message的UInt8数组
    var message: [UInt8] { get }
    /** 追加1和0的计算 */
    func prepare(_ len: Int) -> [UInt8]
    /** 加密方法*/
    func encryptSuccess(sourceString:String) -> String
}

/** 扩展加密协议*/
extension AsymmetricType {
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
}
