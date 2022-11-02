//
//  ChaChaPoly.swift
//  EncryptDecrypt
//
//  Created by 韩增超 on 2022/10/26.
//

import UIKit
import CryptoKit


public class ChaCha20:SymmetricEncryptDecryptProducer {

    private var authenticating: [UInt8]?
    
    private let makeUpKey = "The padding string is automatica"
    /**
     SymmetricKey iOS13后使用
     */
    var chakey:Any?
    
    
    public convenience init(key:String? = nil ,authenticating:String? = nil) {
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
    
    private  func _setAttribute(keyDataString:String? ,authenticatingDataString:String?){
        guard (keyDataString != nil || authenticatingDataString != nil ) else {
            return
        }
        if keyDataString != nil{
            _replacekey(key: keyDataString!)
        }
        if let data:Data = authenticatingDataString?.data(using: .utf8) {
            authenticating = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                    return [UInt8](bytes)
            }
        }
    }
    public  override func replacekey(key: String) {
        _replacekey(key: key)
    }
    /**
     保证加密key的长度为256byte
        -> 32 * 8 = 256
     */
    private func _replacekey(key: String){
        if let keyData = key.data(using:.utf8){
             var useData = keyData
            if keyData.count > 32{
                useData = keyData.subdata(in: 0 ..< 32)
            }else if keyData.count < 32{
                if let makeData = makeUpKey.data(using: .utf8) {
                    let bytes = [UInt8](makeData)
                    useData.append(bytes, count: 32 - keyData.count)
                }
            }
            if let keyString = String(bytes: useData, encoding: .utf8){
                if keyString != key{
                    errorTips(tips: "\(tips_key_length)\(keyString)")
                }
                testKey = keyString
                setChakey(data: useData)
                return
            }else{
                _replacekey(key: makeUpKey)
            }
         }
    }
    func setChakey(data:Data) {
        if #available(iOS 13.0, *) {
            chakey = SymmetricKey(data: data)
        } else {
            chakey = false
            // Fallback on earlier versions
        }
    }
    
    override func runEncryptDecry(data: Data, kState: kEncryptDecrypt) -> Data? {
        if #available(iOS 13.0, *) {
            return _ChaChaPolyEncryptOrDecrypt(kState: kState, data: data)
        } else {
            errorTips(tips: tips_chacha20_no_supported)
            return nil
        }
    }
    @available(iOS 13.0, *)
    private  func _ChaChaPolyEncryptOrDecrypt(kState: kEncryptDecrypt, data: Data) -> Data?{
        if kState == .kDecrypt{
            return _ChaChaPolyDecrypt(data: data, key: chakey as! SymmetricKey, authenticating: authenticating)
        }else{
            return _ChaChaPolyEncrypt(data: data, key: chakey as! SymmetricKey, authenticating: authenticating)
        }
    }
    @available(iOS 13.0, *)
    private func _ChaChaPolyDecrypt<AuthenticatedData>(data: Data, key:SymmetricKey, authenticating:AuthenticatedData?)  -> Data? where AuthenticatedData : DataProtocol {
        if let sealedBox = try? ChaChaPoly.SealedBox(combined: data) {
            var resData:Data?
            if authenticating != nil {
                resData = try? ChaChaPoly.open(sealedBox, using: key, authenticating: authenticating!)
            }else{
                resData = try? ChaChaPoly.open(sealedBox, using: key)
            }
            if resData != nil {
                return resData
            }
        }
        errorTips(tips: error_chacha20_encrypt)
        return Data()
    }
    @available(iOS 13.0, *)
    private func _ChaChaPolyEncrypt<AuthenticatedData>(data: Data, key:SymmetricKey, authenticating:AuthenticatedData?) -> Data? where AuthenticatedData : DataProtocol{
        let poly = ChaChaPoly.Nonce()
        var encryptData:Data?
        if authenticating != nil{
            encryptData = try? ChaChaPoly.seal(data, using: chakey as! SymmetricKey, authenticating: authenticating!).combined
        }else{
            encryptData = try? ChaChaPoly.seal(data, using: chakey as! SymmetricKey, nonce: poly).combined
        }
        return encryptData!
    }
}
