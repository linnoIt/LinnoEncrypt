//
//  ChaChaPoly.swift
//  EncryptDecrypt
//
//  Created by 韩增超 on 2022/10/26.
//

import CryptoKit
import Foundation

public class ChaCha20 : SymmetricEncryptDecryptProducer {
    /** Signature Data */
    private var authenticating: [UInt8]?
    /** default key ，if key length than 256bits use this replenish*/
    private let makeUpKey = "The padding string is automatica"
    /**
     SymmetricKey iOS13后使用
     */
    var chakey:Any?
    /**
     - Parameters:
        - key: 密钥。为空时不再静默生成随机密钥（那会让加密结果永久无法解密），
               而是置空密钥并在加解密时显式报错。
        - authenticating: signing string
     */
    public convenience init(key: String? = nil ,authenticating: String? = nil) {
        self.init()
        _setAttribute(keyDataString: key, authenticatingDataString: authenticating)
    }
    /**
     - Parameters:
        - keyDataString: if data byte  less than 256 ,append default string key
        - authenticatingDataString:signing string
     */
    private  func _setAttribute(keyDataString: String? ,authenticatingDataString: String?) {
        if let keyDataString = keyDataString {
            _replacekey(key: keyDataString)
        }
        if let data:Data = authenticatingDataString?.data(using: .utf8) {
            authenticating = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                    return [UInt8](bytes)
            }
        }
    }
    /**
    install key with string type ,if string data less than256, append default string key
     */
    public  override func replacekey(key: String) {
        _replacekey(key: key)
    }
    
    /**
     - Parameters:
     - data: if data byte  less than 256 ,append default string key
     */
    public  func replaceDataKey(data: Data) {
        if let key = String(data: data, encoding: .utf8) {
            _replacekey(key: key)
        }
    }
    /**
     保证加密key的长度为256bits
        -> 32 * 8 = 256
     */
    private func _replacekey(key: String) {
        guard let data = getBitKey(keyString: key, keyCount: 32) else {
            _replacekey(key: makeUpKey)
            return
        }
        // 截断到 32 字节时可能切断多字节字符（例如中文 key），此时 String(bytes:encoding:.utf8)
        // 会解码失败。但真正的密钥是由 data 构造的 SymmetricKey，密钥本身完全有效，
        // 因此不能因为"文本形式无法还原"就把密钥丢掉——旧实现会让 testKey 保持为空，
        // 加密会被"key 未设置"直接拦截（Debug 下还会断言中断）。
        if let keyString = String(bytes: data, encoding: .utf8) {
            if keyString != key {
                errorTips(tips: "\(tips_key_length)\(keyString)")
            }
            testKey = keyString
        } else {
            // 文本无法无损还原，仅用原 key 作为"密钥已设置"的标记；实际密钥取自上方的 data
            testKey = key
        }
        _setChakey(data: data)
    }
    private func _setChakey(data: Data) {
        if #available(iOS 13.0, *) {
            chakey = SymmetricKey(data: data)
        } else {
            chakey = false
            // Fallback on earlier versions
        }
    }
    
    override func runEncryptDecrypt(data: Data, kState: kEncryptDecrypt) -> Data? {
        if #available(iOS 13.0, *) {
            return _ChaChaPolyEncryptOrDecrypt(kState: kState, data: data)
        } else {
            errorTips(tips: tips_chacha20_no_supported)
            return nil
        }
    }
    @available(iOS 13.0, *)
    private  func _ChaChaPolyEncryptOrDecrypt(kState: kEncryptDecrypt, data: Data) -> Data? {
        guard let key = chakey as? SymmetricKey else {
            errorTips(tips: error_key_not_set)
            assertionFailure(error_key_not_set)
            return nil
        }
        if kState == .kDecrypt {
            return _ChaChaPolyDecrypt(data: data, key: key, authenticating: authenticating)
        } else {
            return _ChaChaPolyEncrypt(data: data, key: key, authenticating: authenticating)
        }
    }
    /**
     decrypt
     - Parameters:
        - data: source data
        - key:decrypt key
        - authenticating:signing data ， can not exist
     - returns: decrypt data
     */
    @available(iOS 13.0, *)
    private func _ChaChaPolyDecrypt<AuthenticatedData>(data: Data, key: SymmetricKey, authenticating: AuthenticatedData?) -> Data? where AuthenticatedData : DataProtocol {
        if let sealedBox = try? ChaChaPoly.SealedBox(combined: data) {
            var resData:Data?
            if let authenticating = authenticating {
                resData = try? ChaChaPoly.open(sealedBox, using: key, authenticating: authenticating)
            } else {
                resData = try? ChaChaPoly.open(sealedBox, using: key)
            }
            if resData != nil {
                return resData
            }
        }
        errorTips(tips: error_chacha20_encrypt)
        return Data()
    }
    /**
     Encrypt
     - Parameters:
        - data: source data
        - key:decrypt key
        - authenticating:signing data ， can not exist
     - returns: Encrypt data
     */
    @available(iOS 13.0, *)
    private func _ChaChaPolyEncrypt<AuthenticatedData>(data: Data, key: SymmetricKey, authenticating: AuthenticatedData?) -> Data? where AuthenticatedData : DataProtocol {
        if let auth = authenticating {
            guard let encryptData = try? ChaChaPoly.seal(data, using: key, authenticating: auth).combined else {
                errorTips(tips: error_chacha20_encrypt)
                return nil
            }
            return encryptData
        }
        let poly = ChaChaPoly.Nonce()
        guard let encryptData = try? ChaChaPoly.seal(data, using: key, nonce: poly).combined else {
            errorTips(tips: error_chacha20_encrypt)
            return nil
        }
        return encryptData
    }
}
