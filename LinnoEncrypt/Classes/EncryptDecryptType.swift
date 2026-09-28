//
//  SymmetricType.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//
//剩下的需要做的
//1 chacha20 支持ios13 以下
//2 非对称加密：P256\P384\P521。

import Foundation

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
        return resData.base64EncodedString()
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

    // MARK: - 无歧义别名（0.2.0 新增，纯追加，既有方法一律保留）
    // 上面 4 个 decrypt(sourceString:) 仅靠返回类型区分，调用点必须显式标注类型，否则报 ambiguous。
    // 下面这组方法名自带返回类型语义，给新代码一条无需类型标注的路径；行为与对应重载完全等价。

    /// 解密为 Data（等价于 `decrypt(sourceString:) as Data`）
    public func decryptToData(sourceString: String) -> Data {
        return decrypt(_stringData(sourceString: sourceString, kState: .kDecrypt))
    }

    /// 解密为 UTF-8 字符串（等价于 `decrypt(sourceString:) as String`）
    public func decryptToString(sourceString: String) -> String {
        if let resString = String(data: decryptToData(sourceString: sourceString), encoding: .utf8) {
            return resString
        }
        return ""
    }

    /// 解密为数组（等价于 `decrypt(sourceString:) as [Any]?`）
    public func decryptToArray(sourceString: String) -> Array<Any>? {
        return getArrayFromJSONString(jsonString: decryptToString(sourceString: sourceString))
    }

    /// 解密为字典（等价于 `decrypt(sourceString:) as [String: Any]?`）
    public func decryptToDictionary(sourceString: String) -> Dictionary<String, Any>? {
        return getDictionaryFromJSONString(jsonString: decryptToString(sourceString: sourceString))
    }

    ///   字符串转data
    private func _stringData(sourceString: String, kState: kEncryptDecrypt) -> Data {
        guard kState != .kEncrypt else {
            return sourceString.data(using: .utf8) ?? Data()
        }
        return Data(base64Encoded: sourceString, options: .ignoreUnknownCharacters) ?? Data()
    }
}
