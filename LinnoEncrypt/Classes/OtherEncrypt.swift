//
//  OtherEncrypt.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import CommonCrypto
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
     */
    public convenience init(key: String, encryption: WayOfEncryption = .CAST, keySize: KeyLength = .maxSize) {
        self.init()
        testKey = key
        self.keySize = keySize
        self.encryption = encryption
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
    
    private override init() {
        super.init()
    }
    override func runEncryptDecrypt(data: Data, kState: kEncryptDecrypt) -> Data {
       return _OtherEncryptOrDecrypt(op: stateOp(kState: kState), data: data, key:testKey)
    }
    
    private  func _OtherEncryptOrDecrypt(op: CCOperation, data: Data, key: String) -> Data {
        let ccKeySize = _keyLengthKeySize(wayOfEncryption: encryption ?? .CAST, keyLength: keySize ?? .maxSize)
        let usekey = getBitKey(oldString: key, keyCount: ccKeySize)
        let alg_blockSize = _encryptionAlgorithm(wayOfEncryption: encryption!)
        return EncryptOrDecrypt(data, (usekey as NSString).utf8String!, op, alg_blockSize.0, CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode), ccKeySize, alg_blockSize.1)
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
        return test[keyLengthFunString]!
    }
}
