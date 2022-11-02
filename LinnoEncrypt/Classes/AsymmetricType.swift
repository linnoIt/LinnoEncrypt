//
//  AsymmetricType.swift
//  QR
//
//  Created by 韩增超 on 2022/10/18.
//

import Foundation

/// 实现：RSA
/// 未实现：Elgamal、背包算法、Rabin、D-H、ECC椭圆曲线加密算法。
/** 扩展协议 的方法去做*/
protocol AsymmetricType:EncryptDecryptType {
    
    var identifierString: String { get  set}
    
}

extension AsymmetricType{
    
    var identifierString: String {
       get { return "" }
       set { /* default set do nothing */ }
    }
    
    /**
     保存密钥到钥匙串
     - Parameters:
        - query: 密钥的参数
     */
    func saveKeyToKeychain(query:Dictionary<String, Any>){
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        assert(status == errSecSuccess, error_save_keychain)
        guard status == errSecSuccess else {
            errorTips(tips: error_save_keychain)
            return
        }
    }
    /**
     创建私钥和公钥
     - Parameters:
        - keySize: 密钥的大小
        - keyType: 密钥的类型
     - returns: 私钥和公钥的元组
     */
    func generateKeyPair(keySize:size_t, keyType:CFString) -> (SecKey, SecKey)?{
        let parameters = [kSecAttrKeyType: keyType,
                          kSecAttrKeySizeInBits: keySize] as [CFString : Any]
        // 创建 privateSecKey
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
            let tipsString = "\(error_create_privateKey) \(String(describing: error))"
            _ = error!.takeRetainedValue() as Error
            assert((error != nil), tipsString)
            errorTips(tips: tipsString)
            return nil
        }
        let publicKey = SecKeyCopyPublicKey(privateKey)
        return (privateKey,publicKey) as? (SecKey, SecKey)
    }
    /**
     将密钥转换为Data
     - Parameters:
        - secKey: 密钥
        - tag: 密钥的tag
        - keyType:  密钥类型
     - returns: 密钥 的data
     */
    func getKeyDataFrom(secKey: SecKey, tag: Data, keyType:CFString) -> Data {
        var data: Data?

        var query = [String: Any]()
        query[kSecClass as String] = kSecClassKey
        query[kSecAttrApplicationTag as String] = tag
        query[kSecAttrKeyType as String] = keyType

        var attributes = query
        attributes[kSecValueRef as String] = secKey
        attributes[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemAdd(attributes as CFDictionary, &result)

        guard status == errSecSuccess else {
            errorTips(tips: error_save_keychain)
            return Data()
        }
        data = result as? Data
        SecItemDelete(query as CFDictionary)
        return data!
    }
    
    /**
     从字符串获取 密钥
     - Parameters:
        - string: 密钥的源字符串
        - keyType: 密钥的类型
        - keySizeInBits: 密钥的大小
        - keyClass: 公钥 || 私钥
     - returns: 返回来自字符串的密钥
     */
    func getKeyWithWithString(_ string:String, _ keyType:CFString, _ keySizeInBits:size_t, _ keyClass: CFString) -> SecKey? {
        var newKey = string
        let spos = newKey.range(of: "-----BEGIN \(keyType) \(keyClass) KEY-----")
        let epos = newKey.range(of: "-----END \(keyType) \(keyClass) KEY-----")
        if spos != nil && epos != nil {
            newKey = String(newKey[spos!.upperBound..<epos!.lowerBound])
        }
        newKey = newKey.replacingOccurrences(of: "\r", with: "")
        newKey = newKey.replacingOccurrences(of: "\n", with: "")
        newKey = newKey.replacingOccurrences(of: "\t", with: "")
        newKey = newKey.replacingOccurrences(of: " ", with: "")
        
        let data = Data.init(base64Encoded: newKey, options: .ignoreUnknownCharacters)
        
        let parameters = [kSecAttrKeyType: keyType,
                        kSecAttrKeySizeInBits: keySizeInBits,
                        kSecAttrKeyClass : keyClass ] as [CFString : Any]
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(data! as CFData, parameters as CFDictionary, &error) else {
            _ = error!.takeRetainedValue() as Error
            let tipsString = "\(error_string_get_secKey) \(String(describing: error))"
            assert((error != nil), tipsString)
            errorTips(tips: tipsString)
            return nil
        }
        return secKey
    }
    
    
    /** 从钥匙串中获取 密钥
     - Parameters:
        - query: 获取的参数
     - returns: 返回来自钥匙串的密钥
     */
    func getKeyWithKeychain(query:Dictionary<String, Any>) -> SecKey?{
        var key: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &key)
        if status == errSecSuccess {
            let result = key as! SecKey
            return result
        }
        errorTips(tips: error_get_keychain)
        return nil
    }
    /**
     从.der证书获取公钥
     - Parameters:
        - path: .der编码证书路径
     - returns: 返回来自der编码证书的的公钥
     */
      func getPublicKeywithDER(_ path: String) -> SecKey? {
        let data: Data;
        do {
            data = try Data.init(contentsOf: URL.init(fileURLWithPath: path))
        } catch {
            errorTips(tips: error_certificates_path)
            return nil
        }
        
        guard let cert = SecCertificateCreateWithData(nil, data as CFData) else {
            errorTips(tips: error_der_notCoding)
            return nil
        }
        let key: SecKey?
        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        if SecTrustCreateWithCertificates(cert, policy, &trust) == noErr {
            var result = SecTrustResultType.invalid
            if trust != nil {
                if SecTrustEvaluate(trust!, &result) == noErr {
                    key = SecTrustCopyPublicKey(trust!)
                    return key
                }
            }
        }
        errorTips(tips: error_public_secKey_null)
        return nil
    }
    
    /**
     从.p12证书获取公钥
     - Parameters:
        - path: .p12证书路径
        - password: ,p12证书密码
     - returns: 返回来自p12证书的的私钥
     */
    func  getPrivateKeyWithP12(_ path: String, with password: String? = "") -> SecKey? {
        let data: Data;
        do {
            data = try Data.init(contentsOf: URL.init(fileURLWithPath: path))
        } catch {
            errorTips(tips: error_certificates_path)
            return nil
        }
        
        var key: SecKey?
        let options = NSMutableDictionary.init()
        options[kSecImportExportPassphrase as String] = password
        var items: CFArray?
        var securityError = SecPKCS12Import(data as CFData, options, &items)
        if securityError == noErr && CFArrayGetCount(items) > 0 {
            let identityDict = CFArrayGetValueAtIndex(items, 0)
            let appKey = Unmanaged.passUnretained(kSecImportItemIdentity).toOpaque()
            let identityApp = CFDictionaryGetValue((identityDict as! CFDictionary), appKey)
            securityError = SecIdentityCopyPrivateKey(identityApp as! SecIdentity, &key)
            if securityError == noErr {
                return key
            }
        }
        errorTips(tips: error_private_secKey_null)
        return nil
    }
}

