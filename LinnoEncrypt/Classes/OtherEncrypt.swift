//
//  OtherEncrypt.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import CommonCrypto
import Foundation
/** CAST，RC4，RC2，Blowfish*/
public final class otherEncry : SymmetricEncryptDecryptProducer {
    
    public enum KeyLength: String {
        case  maxSize = "Max"
        case  minSize = "Min"
    }
    public enum WayOfEncryption: String {
        case  CAST = "CAST"
        case  RC4 = "RC4"
        case  RC2 = "RC2"
        case  Blowfish = "Blowfish"
    }
    // 加密后数据的长度
    private var keySize: KeyLength?
    // 加密类型
    private var encryption: WayOfEncryption?
    /**
     - Parameters:
        -  key :专有的key
        -  encryption: 加密方式，默认为 CAST
        -  keySize: 加密后数据的长度，默认为 maxSize
        -  cipherMode: 工作模式。默认 .ecb（与旧版本密文完全兼容）；
                       需要 CBC 时传 .cbc(iv: nil) 自动生成随机 IV，或传 .cbc(iv: 自己的IV)。
                       注意 RC4 是流密码，不支持 CBC，传入后会报错返回空数据
     */
    public convenience init(key: String, encryption: WayOfEncryption = .CAST, keySize: KeyLength = .maxSize, cipherMode: SymmetricCipherMode = .ecb) {
        self.init()
        testKey = key
        self.keySize = keySize
        self.encryption = encryption
        replaceCipherMode(cipherMode)
    }
    /** 改变加密长度keySize */
    public func replecekeySize(size: KeyLength) {
        keySize = size
    }
    /** 改变加密方式encryption */
    public func repleceEncryption(encryp: WayOfEncryption) {
        encryption = encryp
    }
    /** 改变加密方式encryption和加密长度keySize */
    public func repleceEncryption(encryp: WayOfEncryption, size: KeyLength) {
        replecekeySize(size: size)
        repleceEncryption(encryp: encryp)
    }
    
    /// 供外部（其他模块 / 其他项目）构造；此时 key 为空，调用加解密会按约定报错，不会使用弱默认 key
    public override init() {
        super.init()
    }
    /** 具体算法只提供参数，模式（ECB/CBC）与 IV 处理统一由 EDWithMode 完成 */
    override func runEncryptDecrypt(data: Data, kState: kEncryptDecrypt) -> Data? {
        let useEncryption = encryption ?? .CAST
        let ccKeySize = _keyLengthKeySize(wayOfEncryption: useEncryption, keyLength: keySize ?? .maxSize)
        let alg_blockSize = _encryptionAlgorithm(wayOfEncryption: useEncryption)
        return EDWithMode(data: data, kState: kState, key: testKey, alg: alg_blockSize.0, keyLength: ccKeySize, blockSize: alg_blockSize.1)
    }
}
extension otherEncry {
    /**
     - parameter wayOfEncryption: 加密方式
     - returns  :（CCAlgorithm ，algorithms Block sizes, ）
     */
    private func _encryptionAlgorithm(wayOfEncryption: WayOfEncryption) -> (UInt32, Int) {
        switch wayOfEncryption {
            case .CAST: return (CCAlgorithm(kCCAlgorithmCAST), kCCBlockSizeCAST)
            // RC4 是流密码，没有分组概念。此处沿用的 kCCBlockSizeRC2(8) 仅作为缓冲区对齐粒度参与
            // CCCrypt 的 dataOutAvailable 计算，属历史约定；改动它会改变密文长度，故保持不变。
            case .RC4: return (CCAlgorithm(kCCAlgorithmRC4), kCCBlockSizeRC2)
            case .RC2: return (CCAlgorithm(kCCAlgorithmRC2), kCCBlockSizeRC2)
            case .Blowfish: return (CCAlgorithm(kCCAlgorithmBlowfish), kCCBlockSizeBlowfish)
        }
    }
    private func _defaultKeyLengthString() -> String {
        return "kCCKeySize"
    }
    /**
     - Parameters:
        - wayOfEncryption: 加密方式
        - keyLength: 加密大小
     - returns  : key sizes
     */
    private func _keyLengthKeySize(wayOfEncryption: WayOfEncryption ,keyLength: KeyLength) ->Int {
        let keyLengthFunString = _defaultKeyLengthString().appending(keyLength.rawValue).appending(wayOfEncryption.rawValue)
        let test = ["kCCKeySizeMinCAST":kCCKeySizeMinCAST,
                      "kCCKeySizeMaxCAST":kCCKeySizeMaxCAST,
                      "kCCKeySizeMinRC4":kCCKeySizeMinRC4,
                      "kCCKeySizeMaxRC4":kCCKeySizeMaxRC4,
                      "kCCKeySizeMinRC2":kCCKeySizeMinRC2,
                      "kCCKeySizeMaxRC2":kCCKeySizeMaxRC2,
                      "kCCKeySizeMinBlowfish":kCCKeySizeMinBlowfish,
                      "kCCKeySizeMaxBlowfish":kCCKeySizeMaxBlowfish]
        // wayOfEncryption / keyLength 均来自闭集枚举，组合必然命中上表；
        // 保留 guard 仅为消除强制解包，使异常输入走「Debug 断言 / Release 报错返回 0」的既有失败姿态，
        // 而不是直接崩溃（0 会让 CCCrypt 自行失败，调用方拿到空数据）。
        guard let size = test[keyLengthFunString] else {
            errorTips(tips: "\(error_key_length_not_found)\(keyLengthFunString)")
            assertionFailure("\(error_key_length_not_found)\(keyLengthFunString)")
            return 0
        }
        return size
    }
}
