//
//  _3DES.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//


import CommonCrypto
import Foundation

public final class _3DES : SymmetricEncryptDecryptProducer {
    
    /**
     - Parameters:
        - key       : 专有的 key
        - cipherMode: 工作模式。默认 .ecb（与旧版本密文完全兼容）；
                      需要 CBC 时传 .cbc(iv: nil) 由库自动生成随机 IV，或传 .cbc(iv: 自己的IV)
     */
    public convenience init(key: String, cipherMode: SymmetricCipherMode = .ecb) {
        self.init()
        testKey = key
        replaceCipherMode(cipherMode)
    }
    /// 供外部（其他模块 / 其他项目）构造；此时 key 为空，调用加解密会按约定报错，不会使用弱默认 key
    public override init() {
        super.init()
    }
    /** 具体算法只提供参数，模式（ECB/CBC）与 IV 处理统一由 EDWithMode 完成 */
    override func runEncryptDecrypt(data: Data, kState: kEncryptDecrypt) -> Data? {
        return EDWithMode(data: data, kState: kState, key: testKey, alg: CCAlgorithm(kCCAlgorithm3DES), keyLength: kCCKeySize3DES, blockSize: kCCBlockSize3DES)
    }
}
