//
//  DES.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import CommonCrypto

public final class DES : SymmetricEncryptDecryptProducer {
    
    public convenience init(key: String) {
        self.init()
        testKey = key
    }
    private override init() {
        super.init()
    }
    override func runEncryptDecrypt(data: Data, kState: kEncryptDecrypt) -> Data {
       return DESEncryptOrDecrypt(op: stateOp(kState: kState), data: data, key: testKey)
    }
    /**
     - Parameters:
         - op : CCOperation： 加密还是解密
         - data: 要加密的数据
         - key: 专有的key
     - returns      : 加密或者解密后的数据
     */
    private  func DESEncryptOrDecrypt(op: CCOperation, data: Data, key: String) -> Data {
        let usekey = getBitKey(oldString: key, keyCount: kCCKeySizeDES)
       return EncryptOrDecrypt(data, (usekey as NSString).utf8String!, op, CCAlgorithm(kCCAlgorithmDES), CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode), kCCKeySizeDES, kCCBlockSizeDES)
    }
}
