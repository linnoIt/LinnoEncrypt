//
//  File.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import Foundation
import CommonCrypto

public class SymmetricEncryptDecryptProducer: SymmetricEncryptionBase {

    var testKey = "123456"
    /** 加密 */
    public override func encrypt(_ sourceString: String) -> String {
        assert(sourceString.count > 0,error_length)
        return runEncryptDecry(data: stringData(sourceString: sourceString, kState: .kEncrypt), kState: .kEncrypt)
    }
    /** 解密 */
    public override func decrypt(_ sourceString: String) -> String {
        assert(sourceString.count > 0,error_length)
        return runEncryptDecry(data: stringData(sourceString: sourceString, kState: .kDecrypt), kState: .kDecrypt)
    }
    /** 修改加密的key */
    public func replacekey(key:String){
        testKey = key
    }
    func runEncryptDecry(data:Data, kState: kEncryptDecrypt) -> String{
        encryptAbstractMethod()
    }
}
extension SymmetricEncryptDecryptProducer{
    // 将字符串转为data
    func stringData(sourceString: String, kState:kEncryptDecrypt) -> Data{
        guard kState != .kEncrypt else {
            return sourceString.data(using: .utf8) ?? Data()
        }
        return Data(base64Encoded: sourceString, options: .ignoreUnknownCharacters) ?? Data()
    }
    
    // 保证key的长度和算法长度对应位
    func getBitKey(oldString:String, keyCount:Int) -> String {
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
        加密解密的核心方法
     */
    final internal func EncryptOrDecrypt(_ data:Data, _ key:UnsafeRawPointer, _ op:CCOperation, _ alg:CCAlgorithm, _ options: CCOptions, _ keyLength:Int, _ blockSize:Int)  -> String{
        let stringBufferSize    = size_t(data.count)
        let bufferPtrSize       = (stringBufferSize + blockSize) & ~(blockSize - 1)

        let dataBytes           = (data as NSData).bytes
        let bufferPtr           = malloc(bufferPtrSize * MemoryLayout<UInt8>.size)
        
        memset(bufferPtr, 0x0, bufferPtrSize)
        
        var movedBytes:size_t   = 0
        
        let res = CCCrypt(op,
                alg,
                options,
                key,
                keyLength,
                nil,
                dataBytes,
                stringBufferSize,
                bufferPtr,
                bufferPtrSize,
                &movedBytes)
        
        let resData = Data.init(bytes: bufferPtr!, count: movedBytes)
        var resString:String
        assert(res == kCCSuccess,"\(error_encrypt_decrypt)\(res)")
        guard res == kCCSuccess else {
            return "\(error_encrypt_decrypt)\(res)"
        }
        if op == 0 {
            resString  = resData.base64EncodedString(options: .lineLength64Characters)
        }else{
            resString = String(data: resData, encoding: .utf8) ?? error_base64_Decoding
        }
        free(bufferPtr)
        return resString
    }
    func stateOp(kState:kEncryptDecrypt) -> UInt32 {
        if kState == .kEncrypt{
            return UInt32(CCOperation(kCCEncrypt))
        }
        return UInt32(CCOperation(kCCDecrypt))
    }
}
