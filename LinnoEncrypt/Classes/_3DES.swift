//
//  _3DES.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import Foundation
import CommonCrypto

public final class _3DES: SymmetricEncryptDecryptProducer {
    
    public convenience init( key:String) {
        self.init()
        testKey = key
    }
    private override init() {
        super.init()
    }
    override func runEncryptDecry(data: Data, kState: kEncryptDecrypt) -> Data {
       return _3DESEncryptOrDecrypt(op: stateOp(kState: kState), data: data, key: testKey)
    }
    /**
     3DES的加密过程 和 解密过程
     - parameter op : CCOperation： 加密还是解密
     CCOperation（kCCEncrypt）加密
     CCOperation（kCCDecrypt) 解密
     - parameter data: 要加密的数据
     - parameter key: 专有的key,一个钥匙一般
     - returns      : 加密或者解密后的字符
     */
    private  func _3DESEncryptOrDecrypt(op: CCOperation, data: Data, key:String) -> Data{
        let usekey = getBitKey(oldString: key, keyCount: kCCKeySize3DES)
       return EncryptOrDecrypt(data, (usekey as NSString).utf8String!, op, CCAlgorithm(kCCAlgorithm3DES), CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode), kCCKeySize3DES, kCCBlockSize3DES)
    }
}
