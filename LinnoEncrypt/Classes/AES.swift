//
//  AES.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import CommonCrypto
/** AES*/
public final class AES : SymmetricEncryptDecryptProducer {
    
    public enum AESkeySize {
        case  AES128
        case  AES192
        case  AES256
    }
    var keySize: AESkeySize?
    
    public convenience init(key: String, keySize: AESkeySize = .AES192) {
        self.init()
        testKey = key
        self.keySize = keySize
    }
    private override init() {
        super.init()
    }
    /** change keysize */
    public func replecekeySize(size: AESkeySize) {
        keySize = size
    }
    override func runEncryptDecrypt(data: Data, kState: kEncryptDecrypt) -> Data {
       return _AESEncryptOrDecrypt(op: stateOp(kState: kState), data: data, key:testKey)
    }
    /** - Parameters:
         - op : CCOperation： 加密还是解密
         -  data: 要加密的数据
         - key: 专有的key
        - returns  : 加密或者解密后的数据
     */
    private  func _AESEncryptOrDecrypt(op: CCOperation, data: Data, key: String) -> Data {
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
        return EncryptOrDecrypt(data, (usekey as NSString).utf8String!, op, CCAlgorithm(alg), CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode), ccKeySize ,kCCBlockSizeAES128)
    }
}
