//
//  SymmetricType.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//
//剩下的需要做的
//1 chacha20 支持ios13 以下
//2 非对称加密：P256\P384\P521。

public enum kEncryptDecrypt {
    case kEncrypt
    case kDecrypt
}
public protocol EncryptDecryptType {
    
    // MARK: 真正加密解密的数据方法 需要子类实现
    func encrypt(_ sourceData: Data) -> Data
    
    func decrypt(_ sourceData: Data) -> Data
    
    // MARK: 加密
    // data类型
    func encrypt(sourceData: Data) -> String
    // 字符串类型
    func encrypt(sourceString: String) -> String
    // 数组 转换为json 后加密
    func encrypt(sourceArray: Array<Any>) -> String?
    // 字典 转换为json 后加密
    func encrypt(sourceDictionary: Dictionary<String, Any>) -> String?
    
    // MARK: 解密
    // 解密为data
    func decrypt(sourceString: String) -> Data
    // 解密为字符串
    func decrypt(sourceString: String) -> String
    // 解密为数组，非json数据可能会失败
    func decrypt(sourceString: String) -> Array<Any>?
    // 解密为字典，非json数据可能会失败
    func decrypt(sourceString: String) -> Dictionary<String, Any>?

}

extension EncryptDecryptType{
    /** 加密*/
    public func encrypt(sourceData: Data) -> String {
        let resData = encrypt(sourceData)
        return resData.base64EncodedString(options: .lineLength64Characters)

    }
    public func encrypt(sourceString: String) -> String {
        return encrypt(sourceData:_stringData(sourceString: sourceString, kState: .kEncrypt))
    }
    
    public func encrypt(sourceArray: Array<Any>) -> String? {
        if let json = getJSONStringFromAny(obj: sourceArray) {
            return encrypt(sourceString:json)
        }
        return nil
    }
    public func encrypt(sourceDictionary: Dictionary<String, Any>) -> String? {
        if let json = getJSONStringFromAny(obj: sourceDictionary) {
            return encrypt(sourceString:json)
        }
        return nil
    }
    /** 解密*/
    public func decrypt(sourceString: String) -> Data {
        return decrypt(_stringData(sourceString: sourceString, kState:.kDecrypt))
    }
    
    public func decrypt(sourceString: String) -> String {
        if let resString = String(data: decrypt(sourceString: sourceString), encoding: .utf8) {
            return resString
        }
        return ""
    }
    public func decrypt(sourceString: String) -> Array<Any>? {
        if let res = getArrayFromJSONString(jsonString: decrypt(sourceString: sourceString)) {
            return res
        }
        return nil
    }
    public func decrypt(sourceString: String) -> Dictionary<String, Any>? {
        if let res = getDictionaryFromJSONString(jsonString: decrypt(sourceString: sourceString)) {
            return res
        }
        return nil
    }
    ///   字符串转data
    private func _stringData(sourceString: String, kState: kEncryptDecrypt) -> Data {
        guard kState != .kEncrypt else {
            return sourceString.data(using: .utf8) ?? Data()
        }
        return Data(base64Encoded: sourceString, options: .ignoreUnknownCharacters) ?? Data()
    }
}
