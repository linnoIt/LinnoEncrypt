//
//  File.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import Foundation
import CommonCrypto

class SymmetricEncryptDecryptProducer: SymmetricEncryptionBase {

    var testKey = "123456"
    override func encryptDecryptSuccess(sourceString: String, kState: kEncryptDecrypt = .kEncrypt) -> String {
        guard sourceString.count > 0  else{
            return "sourceSting is empty"
        }
        return runEncryptDecry(data: stringData(sourceString: sourceString, kState: kState), kState: kState)
    }
    func replacekey(key:String){
        testKey = key
    }
    func runEncryptDecry(data:Data, kState: kEncryptDecrypt) -> String{
        return "error"
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
    
    final internal func EncryptOrDecrypt(_ data:Data, _ key:UnsafeRawPointer, _ op:CCOperation, _ alg:CCAlgorithm, _ options: CCOptions, _ keyLength:Int)  -> String{
        
        let stringBufferSize    = size_t(data.count)
        let bufferPtrSize       = (stringBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1)

        let dataBytes           = (data as NSData).bytes
        let bufferPtr           = malloc(bufferPtrSize * MemoryLayout<UInt8>.size)
        
        memset(bufferPtr, 0x0, bufferPtrSize)
        
        var movedBytes:size_t   = 0
        
        CCCrypt(op,
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
        if op == 0 {
            resString  = resData.base64EncodedString(options: .lineLength64Characters)
        }else{
            resString = String(data: resData, encoding: .utf8) ?? "Decrypt Error"
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
