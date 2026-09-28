//
//  Curve25519.swift
//  EncryptDecrypt
//
//  Created by 韩增超 on 2022/11/3.
//

import CryptoKit
import Foundation
///  Curve_25519
///  功能一：验签
///
///  功能二： 生成非对称密钥Curve25519（1、签名密钥Signing。2、加密密钥KeyAgreement）、共享密钥SharedSecret、对称密钥SymmetricKey
///
@available(iOS 13.0, *)
public struct Curve_25519 {
    
    public enum SymmetricKeyCount: Int {
        // SymmetricKeySize/8
        case byte16 = 16    // 128bits
        case byte24 = 24    // 192bits
        case byte32 = 32    // 256bits
    }
    // 生成本地加密私钥
     public static func generateLocalPrivateKey(data: Data? = nil) -> Curve25519.KeyAgreement.PrivateKey? {
        // 旧实现的分支写反了：data 为 nil（默认调用）时会走 else 分支并对 nil 强解包而崩溃；
        // data 非 nil 时又直接返回新随机密钥、把 data 丢掉。这里按原意修正为：
        // 不传 data → 生成新密钥；传了 data → 用 data 还原密钥。
        guard let data = data else {
            return Curve25519.KeyAgreement.PrivateKey()
        }
        if let res = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data) {
            return res
        }
        errorTips(tips: error_curve_25519_data_generate_key_error)
        return nil
    }
    // 获取服务器公钥数据生成服务器公钥
    public static func generateServerPublicKey<D>(data: D) -> Curve25519.KeyAgreement.PublicKey?  where D : ContiguousBytes {
        if let key = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: data){
            return key
        }
        errorTips(tips: error_curve_25519_data_generate_key_error)
        return nil
    }
    // 生成共享密钥
    public static func generateSharedKey(privateKey: Curve25519.KeyAgreement.PrivateKey, otherPublicKey:  Curve25519.KeyAgreement.PublicKey) -> SharedSecret? {
        if let sharedKey = try? privateKey.sharedSecretFromKeyAgreement(with: otherPublicKey) {
            return sharedKey
        }
        errorTips(tips: error_curve_25519_shared_key_error)
        return nil
    }
    // 生成hkdf类型的对称密钥
    public static func generatehkdfSymmetricKey<H:HashFunction>(sharedKey: SharedSecret,
                                                        salt: Data,
                                                        shardInfo: Data,
                                                                hashFunc: H.Type = CryptoKit.SHA256.self,
                                                        keySize: SymmetricKeyCount = .byte16) -> SymmetricKey {
       let derivedSymmetricKey = sharedKey.hkdfDerivedSymmetricKey(using:hashFunc, salt: salt, sharedInfo: shardInfo, outputByteCount: keySize.rawValue)
        return derivedSymmetricKey
    }
    // 生成X963类型的对称密钥
    public static func generateX963SymmetricKey<H:HashFunction>(sharedKey: SharedSecret,
                                                         shardInfo: Data,
                                                                hashFunc: H.Type = CryptoKit.SHA256.self,
                                                         keySize: SymmetricKeyCount = .byte16) -> SymmetricKey {
        let derivedSymmetricKey = sharedKey.x963DerivedSymmetricKey(using:hashFunc, sharedInfo: shardInfo, outputByteCount: keySize.rawValue)
        return derivedSymmetricKey
    }
    
    // 生成验签私钥
    public static func generateSigningPrinvateKey(data: Data? = nil) -> Curve25519.Signing.PrivateKey? {
        // 同 generateLocalPrivateKey：修正原实现写反的分支与 nil 强解包
        guard let data = data else {
            return Curve25519.Signing.PrivateKey()
        }
        if let res = try? Curve25519.Signing.PrivateKey(rawRepresentation: data) {
            return res
        }
        errorTips(tips: error_curve_25519_data_generate_key_error)
        return nil
    }
    // 生成验签公钥
    public static func generateSigningPublicKey<D>(privateKey: Curve25519.Signing.PrivateKey? = nil, data: D? = nil) -> Curve25519.Signing.PublicKey?  where D : ContiguousBytes {
        if let privateKey = privateKey {
            return privateKey.publicKey
        }
        if let data = data, let key = try? Curve25519.Signing.PublicKey(rawRepresentation: data) {
            return key
        }
        errorTips(tips: error_curve_25519_data_generate_key_error)
        return nil
    }
    // 对数据签名
    public static func signing(signingString: String, signingKey: Curve25519.Signing.PrivateKey) -> Data? {
        if let data = signingString.data(using: .utf8) {
            if let signature = try? signingKey.signature(for: data) {
                return signature
            }
        }
        errorTips(tips: error_curve_25519_signing_error)
        return nil
    }
    
    // 验证签名
    public static func isValidSignature(signingPublicKeyData: Data, signature: Data, sourceData: Data) -> Bool {
        if let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: signingPublicKeyData) {
            if publicKey.isValidSignature(signature, for: sourceData){
                return true
            }
        }
        return false
    }
}
