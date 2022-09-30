//
//  AES.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import Foundation
import CommonCrypto

/** AES*/
final class AES: SymmetricEncryptDecryptProducer {
    
    public enum AESkeySize{
        case  AES128
        case  AES192
        case  AES256
    }
    var keySize:AESkeySize?
    
    convenience init( key:String, keySize:AESkeySize = .AES192) {
        self.init()
        testKey = key
        self.keySize = keySize
    }
    private override init() {
        super.init()
    }
    override func runEncryptDecry(data: Data, kState: kEncryptDecrypt) -> String {
       return _AESEncryptOrDecrypt(op: stateOp(kState: kState), data: data, key:testKey)
    }
    func replecekeySize(size:AESkeySize) {
        keySize = size
    }
    
    /**
     AES的加密过程 和 解密过程
     */
    private  func _AESEncryptOrDecrypt(op: CCOperation, data: Data, key:String) -> String{
        var ccKeySize:Int
        var alg:Int = kCCAlgorithmAES
        switch keySize {
        case .AES128: ccKeySize = kCCKeySizeAES128;alg = kCCAlgorithmAES128
        case .AES192: ccKeySize = kCCKeySizeAES192
        case .AES256: ccKeySize = kCCKeySizeAES256
        case .none:
            ccKeySize = kCCKeySizeAES192
        }

       let usekey = getBitKey(oldString: key, keyCount: ccKeySize)
       return EncryptOrDecrypt(data, (usekey as NSString).utf8String!, op, CCAlgorithm(alg), CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode), ccKeySize)
    }
}
