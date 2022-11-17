//
//  ChaChaPoly.swift
//  EncryptDecrypt
//
//  Created by 韩增超 on 2022/10/26.
//

import CryptoKit

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
        - key: key
        - authenticating:signing string
     */
    public convenience init(key: String? = nil ,authenticating: String? = nil) {
        self.init()
        _setAttribute(keyDataString: key, authenticatingDataString: authenticating)
        guard chakey != nil else{
            if #available(iOS 13.0, *) {
                chakey = SymmetricKey(size: .bits256)
            } else {
                // Fallback on earlier versions
            }
            return
        }
        
    }
    /**
     - Parameters:
        - keyDataString: if data byte  less than 256 ,append default string key
        - authenticatingDataString:signing string
     */
    private  func _setAttribute(keyDataString: String? ,authenticatingDataString: String?) {
        if keyDataString != nil {
            _replacekey(key: keyDataString!)
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
        if let data = getBitKey(keyString: key, keyCount: 32) {
            if let keyString = String(bytes: data, encoding: .utf8) {
                if keyString != key {
                    errorTips(tips: "\(tips_key_length)\(keyString)")
                }
                testKey = keyString
                _setChakey(data: data)
                return
            }
        } else {
            _replacekey(key: makeUpKey)
        }
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
        if kState == .kDecrypt {
            return _ChaChaPolyDecrypt(data: data, key: chakey as! SymmetricKey, authenticating: authenticating)
        } else {
            return _ChaChaPolyEncrypt(data: data, key: chakey as! SymmetricKey, authenticating: authenticating)
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
            if authenticating != nil {
                resData = try? ChaChaPoly.open(sealedBox, using: key, authenticating: authenticating!)
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
        let poly = ChaChaPoly.Nonce()
        var encryptData:Data?
        if authenticating != nil {
            encryptData = try? ChaChaPoly.seal(data, using: chakey as! SymmetricKey, authenticating: authenticating!).combined
        } else {
            encryptData = try? ChaChaPoly.seal(data, using: chakey as! SymmetricKey, nonce: poly).combined
        }
        return encryptData!
    }
}
