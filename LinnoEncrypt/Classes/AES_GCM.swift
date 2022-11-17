//
//  AES_GCM.swift
//  EncryptDecrypt
//
//  Created by 韩增超 on 2022/11/16.
//

import CryptoKit

@available(iOS 13.0, *)
public final class AES_GCM : SymmetricEncryptDecryptProducer {
    
    var symmetricKey: SymmetricKey?
    /**
     - Parameter key： If you want to use AES-GCM, Use Curve-25519 to generate SymmetricKey
     */
    public convenience init(key: SymmetricKey) {
        self.init()
        symmetricKey = key
    }
    private override init() {
        super.init()
    }
    
    override func runEncryptDecrypt(data: Data, kState: kEncryptDecrypt) -> Data? {
        if let key = symmetricKey {
            guard kState == .kDecrypt else {
                return _encrypt(data: data, key: key)
            }
            return _decrypt(data: data, key: key)
        }
        return nil
    }
    

    @available(iOS 15.0, *)
    public static func wrapKey(keyToWrap: SymmetricKey, key: SymmetricKey) -> Data? {
        _wrapKey(keyToWrap: keyToWrap, using: key)
        
    }
    @available(iOS 15.0, *)
    public static func unWrapKey(wrapped: Data, using: SymmetricKey) -> SymmetricKey? {
        _unWrapKey(wrapped: wrapped, using: using)
    }

}
@available(iOS 13.0, *)
extension AES_GCM {
    
    /** 加密*/
    private func _encrypt(data: Data, key: SymmetricKey) -> Data? {
        let poly = CryptoKit.AES.GCM.Nonce()
        if  let AES_GCM_SealedBox = try? CryptoKit.AES.GCM.seal(data, using: key,nonce: poly){
            return AES_GCM_SealedBox.combined
        }
        errorTips(tips: error_AES_GCM_encrypt_error)
        return nil
    }
    /** 解密*/
    private func _decrypt(data: Data, key: SymmetricKey) -> Data? {
        if let sealedBox = try? CryptoKit.AES.GCM.SealedBox(combined: data) {
            if let res = try? CryptoKit.AES.GCM.open(sealedBox, using: key) {
                return res
            }
        }
        errorTips(tips: error_AES_GCM_decrypt_error)
        return nil
    }
    
    ///  使用AES.GCM 加密 和解密
    ///  使用AES wrap 包装密钥 为Data
    
    /** 包装key*/
    @available(iOS 15.0, *)
    private static func _wrapKey(keyToWrap: SymmetricKey, using: SymmetricKey) -> Data? {
        if let res = try? CryptoKit.AES.KeyWrap.wrap(keyToWrap, using: using) {
            return res
        }
        errorTips(tips: error_AES_GCM_wrapKey_error)
        return nil
    }
    /** 解包key*/
    @available(iOS 15.0, *)
    private static func _unWrapKey(wrapped: Data, using: SymmetricKey) -> SymmetricKey? {
        if let res = try? CryptoKit.AES.KeyWrap.unwrap(wrapped, using: using) {
            return res
        }
        errorTips(tips: error_AES_GCM_unWrapKey_error)
        return nil
    }
}

