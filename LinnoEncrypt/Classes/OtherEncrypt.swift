//
//  OtherEncrypt.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import Foundation
import CommonCrypto
/** CAST，RC4，RC2，Blowfish*/
public final class otherEncry: SymmetricEncryptDecryptProducer {
    
    public enum KeyLength:String{
        case  maxSize = "Max"
        case  minSize = "Min"
    }
    public enum WayOfEncryption:String{
        case  CAST = "CAST"
        case  RC4 = "RC4"
        case  RC2 = "RC2"
        case  Blowfish = "Blowfish"
        
    }
    private var keySize:KeyLength?
    private var encryption:WayOfEncryption?
    
    public convenience init( key:String, encryption:WayOfEncryption = .CAST, keySize:KeyLength = .maxSize) {
        self.init()
        testKey = key
        self.keySize = keySize
        self.encryption = encryption
    }
    public func replecekeySize(size:KeyLength) {
        keySize = size
    }
    public func repleceEncryption(encryp:WayOfEncryption) {
        encryption = encryp
    }
    public func repleceEncryption(encryp:WayOfEncryption, size:KeyLength) {
        replecekeySize(size: size)
        repleceEncryption(encryp: encryp)
    }
    
    private override init() {
        super.init()
    }
    override func runEncryptDecry(data: Data, kState: kEncryptDecrypt) -> String {
       return _OtherEncryptOrDecrypt(op: stateOp(kState: kState), data: data, key:testKey)
    }
    
    private  func _OtherEncryptOrDecrypt(op: CCOperation, data: Data, key:String) -> String{
        let ccKeySize = keyLengthKeySize(wayOfEncryption: encryption ?? .CAST, keyLength: keySize ?? .maxSize)
        let usekey = getBitKey(oldString: key, keyCount: ccKeySize)
        let alg_blockSize = encryptionAlgorithm(wayOfEncryption: encryption!)
        return EncryptOrDecrypt(data, (usekey as NSString).utf8String!, op, alg_blockSize.0 , CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode), ccKeySize, alg_blockSize.1)
    }
}
extension otherEncry{
    fileprivate func encryptionAlgorithm(wayOfEncryption:WayOfEncryption) -> (UInt32, Int) {
        switch wayOfEncryption {
        case .CAST: return (CCAlgorithm(kCCAlgorithmCAST), kCCBlockSizeCAST)
        case .RC4: return (CCAlgorithm(kCCAlgorithmRC4), kCCBlockSizeRC2)
        case .RC2: return (CCAlgorithm(kCCAlgorithmRC2), kCCBlockSizeRC2)
        case .Blowfish: return (CCAlgorithm(kCCAlgorithmBlowfish), kCCBlockSizeBlowfish)
        }
    }
    private func defaultKeyLengthString() -> String{
        return "kCCKeySize"
    }
    fileprivate func keyLengthKeySize(wayOfEncryption:WayOfEncryption ,keyLength:KeyLength) ->Int{
        let keyLengthFunString = defaultKeyLengthString().appending(keyLength.rawValue).appending(wayOfEncryption.rawValue)
        let test =   ["kCCKeySizeMinCAST":kCCKeySizeMinCAST,
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
