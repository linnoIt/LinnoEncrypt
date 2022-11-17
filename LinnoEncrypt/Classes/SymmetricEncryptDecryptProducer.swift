//
//  File.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import CommonCrypto

public class SymmetricEncryptDecryptProducer : SymmetricEncryptionBase {
    private let makeUpKey = "The padding string is automatica"
    var testKey = "123456"

    public override func encrypt(_ sourceData: Data) -> Data {
        _EDRun(data: sourceData, kState: .kEncrypt)
    }
    
    public override func decrypt(_ sourceData: Data) -> Data {
        _EDRun(data: sourceData, kState: .kDecrypt)
    }
    
    private func _EDRun(data: Data, kState: kEncryptDecrypt) -> Data {
        guard data.count > 0 else {
            errorTips(tips: error_length)
            return Data()
        }
        if let resData = runEncryptDecrypt(data: data, kState: kState) {
            return resData
        }
        errorTips(tips: error_length)
        return Data()
    }
    /** 修改加密的key */
    public func replacekey(key: String) {
        testKey = key
    }
    
    func runEncryptDecrypt(data: Data, kState: kEncryptDecrypt) -> Data? {
        encryptAbstractMethod()
    }
}
extension SymmetricEncryptDecryptProducer {
    /**
     保证key的长度和算法长度对应位
     */
    func getBitKey(oldString: String, keyCount: Int) -> String {
        guard oldString.count != keyCount else{
            return oldString
        }
        var newString:String
        if oldString.count > keyCount {
            newString = String(oldString.prefix(keyCount))
        }else{
            newString = oldString.appendingFormat(String(format: "%%0%lud", keyCount - oldString.count) ,0)
        }
        return newString
    }
    /**
     保证key的长度和算法长度对应位（chacha20、AES_GCM的key为data数据转SymmetricKey，无法添加0为补充）
     */
    func getBitKey(keyString: String, keyCount: Int) -> Data? {
        if let keyData = keyString.data(using:.utf8) {
             var useData = keyData
            if keyData.count > keyCount {
                useData = keyData.subdata(in: 0 ..< keyCount)
            } else if keyData.count < keyCount {
                if let makeData = makeUpKey.data(using: .utf8) {
                    let bytes = [UInt8](makeData)
                    useData.append(bytes, count: keyCount - keyData.count)
                }
            }
            return useData
        }
        return nil
    }
    /**
     对称 加密解密的核心方法 （不包含chacha20、AES_GCM）
     - Parameters:
        -  data : 原始的数据
        -  key : key
        -  op: 加密｜解密
        -  alg: 类型
        -  options: 补码方式
        -  keyLength: key长度
        - blockSize: 用来计算缓冲区及接受数据大小
     - returns   : 加解密后的数据
     */
    final internal func EncryptOrDecrypt(_ data: Data,
                                         _ key: UnsafeRawPointer,
                                         _ op: CCOperation,
                                         _ alg: CCAlgorithm,
                                         _ options: CCOptions,
                                         _ keyLength: Int,
                                         _ blockSize: Int)  -> Data {
        
        let stringBufferSize    = size_t(data.count)
        let bufferPtrSize       = (stringBufferSize + blockSize) & ~(blockSize - 1)

        let dataBytes           = (data as NSData).bytes
        let bufferPtr           = malloc(bufferPtrSize * MemoryLayout<UInt8>.size)
        
        memset(bufferPtr, 0x0, bufferPtrSize)
        
        var movedBytes:size_t   = 0
        
        let res = CCCrypt(op,                // op: CCOperation 加密 | 解密
                          alg,               // alg: CCAlgorithm 加密算法标准
                          options,           // options:CCOptions 补码方式，默认CBC，可选择ECB
                          key,               // key:UnsafeRawPointer 加解密的密钥
                          keyLength,         // keyLength:Int 加解密key的长度
                          nil,               // iv:UnsafeRawPointer,偏移向量，CBC模式下需要；默认16位0，ECB模式不需要
                          dataBytes,         // dataIn:加解密数据的byte
                          stringBufferSize,  // dataInLength: 加解密数据的长度
                          bufferPtr,         // dataOut:加解密后的数据总数据的大小
                          bufferPtrSize,     // dataOutAvailable:加解缓冲区的大小
                          &movedBytes)       // dataOutMoved:加解密成功之后写入的地址
        // 截取加解密成功后的地址
        let resData = Data.init(bytes: bufferPtr!, count: movedBytes)
        assert(res == kCCSuccess,"\(error_encrypt_decrypt)\(res)")
        guard res == kCCSuccess else {
            errorTips(tips: "\(error_encrypt_decrypt)\(res)")
            return Data()
        }
        free(bufferPtr)
        return resData
    }
    /**
     设置加解密状态
     */
    func stateOp(kState: kEncryptDecrypt) -> UInt32 {
        if kState == .kEncrypt{
            return UInt32(CCOperation(kCCEncrypt))
        }
        return UInt32(CCOperation(kCCDecrypt))
    }
}
