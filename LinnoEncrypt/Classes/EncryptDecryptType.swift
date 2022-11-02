//
//  SymmetricType.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import Foundation

//剩下的需要做的
//1 chacha20 支持ios13 以下
//2 非对称加密：Curve25519、P256\P384\P521。

public enum kEncryptDecrypt {
    case kEncrypt
    case kDecrypt
}
public protocol EncryptDecryptType {
    
    /**  加密解密的数据方法 需要子类实现 */
    func encrypt(_ sourceData:Data) -> Data
    
    func decrypt(_ sourceData:Data) -> Data
    
    /** 加密*/
    func encrypt(sourceData:Data) -> String
    
    func encrypt(sourceString:String) -> String
    
    func encrypt(sourceArray:Array<Any>) -> String
    
    func encrypt(sourceDictionary:Dictionary<String, Any>) -> String
    
    /** 解密*/
    
    func decrypt(sourceString:String) -> String
    
    func decrypt(sourceString:String) -> Data
    
    func decrypt(sourceString:String) -> Array<Any>?
    
    func decrypt(sourceString:String) -> Dictionary<String, Any>?
    
}

extension EncryptDecryptType{
    /** 加密*/
    public func encrypt(sourceData:Data) -> String{
        let resData = encrypt(sourceData)
        return resData.base64EncodedString(options: .lineLength64Characters)

    }
    public func encrypt(sourceString:String) -> String{
        return encrypt(sourceData:_stringData(sourceString: sourceString, kState: .kEncrypt))
    }
    
    public func encrypt(sourceArray:Array<Any>) -> String{
        if let json = getJSONStringFromAny(obj: sourceArray){
            return encrypt(sourceString:json)
        }
        return ""
    }
    
    public func encrypt(sourceDictionary:Dictionary<String, Any>) -> String{
        if let json = getJSONStringFromAny(obj: sourceDictionary){
            return encrypt(sourceString:json)
        }
        return ""
    }
    /** 解密*/
    
    public func decrypt(sourceString:String) -> String{
        if let resString = String(data: decrypt(sourceString: sourceString), encoding: .utf8){
            return resString
        }
        return ""
    }
    
    public func decrypt(sourceString:String) -> Data{
        return decrypt(_stringData(sourceString: sourceString, kState:.kDecrypt))
    }
    
    public func decrypt(sourceString:String) -> Array<Any>?{
        if let res = getArrayFromJSONString(jsonString: decrypt(sourceString: sourceString)){
            return res
        }
        return nil
    }
    public func decrypt(sourceString:String) -> Dictionary<String, Any>?{
        if let res = getDictionaryFromJSONString(jsonString: decrypt(sourceString: sourceString)){
            return res
        }
        return nil
    }
    ///   字符串转data
    func _stringData(sourceString: String, kState:kEncryptDecrypt) -> Data{
        guard kState != .kEncrypt else {
            return sourceString.data(using: .utf8) ?? Data()
        }
        return Data(base64Encoded: sourceString, options: .ignoreUnknownCharacters) ?? Data()
    }
}
