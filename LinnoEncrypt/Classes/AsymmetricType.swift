//
//  AsymmetricType.swift
//  QR
//
//  Created by 韩增超 on 2022/10/18.
//

import Foundation
import Security

/// 实现：RSA
/** 扩展协议 的方法去做*/
protocol AsymmetricType : EncryptDecryptType {
    
    var identifierString: String { get  set}
    
}

extension AsymmetricType {
    
    var identifierString: String {
       get { return "" }
       set { /* default set do nothing */ }
    }
    /**
     保存密钥到钥匙串
     - Parameters:
        - query: 密钥的参数
     */
    func saveKeyToKeychain(query: Dictionary<String, Any>) {
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
    func generateKeyPair(keySize: size_t, keyType: CFString) -> (SecKey, SecKey)? {
        let parameters = [kSecAttrKeyType: keyType,
                          kSecAttrKeySizeInBits: keySize] as [CFString : Any]
        // 创建 privateSecKey
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
            // 顺序不可调换：
            //  1) 先取错误描述 —— 此时 CFError 仍存活；
            //  2) 再 takeRetainedValue() 消费掉 Unmanaged 持有的引用（否则泄漏）；
            //  3) 断言用第 1 步的布尔快照，不再触碰已被消费的 error。
            // 若把 (2) 提到 (1) 之前，后续 String(describing: error) 访问的是已释放对象，
            // 会触发 use-after-free（实测 EXC_BREAKPOINT / SIGTRAP）。
            let tipsString = "\(error_create_privateKey) \(String(describing: error))"
            let hasError = (error != nil)
            _ = error?.takeRetainedValue()
            assert(hasError, tipsString)
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
    func getKeyDataFrom(secKey: SecKey, tag: Data, keyType: CFString) -> Data {
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
        SecItemDelete(query as CFDictionary)
        guard let keyData = result as? Data else {
            errorTips(tips: error_save_keychain)
            return Data()
        }
        return keyData
    }
    
    /**
     将字符串转为Data 从getKeyWithData方法获取 密钥
     - Parameters:
        - string: 密钥的源字符串
        - keyType: 密钥的类型
        - keySizeInBits: 密钥的大小
        - keyClass: 公钥 || 私钥
     - returns: 返回来自字符串的密钥
     */
    func getKeyWithString(_ string: String, _ keyType: CFString, _ keySizeInBits: size_t, _ keyClass: CFString) -> SecKey? {
        var newKey = string
        let spos = newKey.range(of: "-----BEGIN \(keyType) \(keyClass) KEY-----")
        let epos = newKey.range(of: "-----END \(keyType) \(keyClass) KEY-----")
        if let spos = spos, let epos = epos {
            newKey = String(newKey[spos.upperBound..<epos.lowerBound])
        }
        newKey = newKey.replacingOccurrences(of: "\r", with: "")
        newKey = newKey.replacingOccurrences(of: "\n", with: "")
        newKey = newKey.replacingOccurrences(of: "\t", with: "")
        newKey = newKey.replacingOccurrences(of: " ", with: "")
        
        if let data = Data.init(base64Encoded: newKey, options: .ignoreUnknownCharacters) {
           return  getKeyWithData(data as CFData, keyType, keySizeInBits, keyClass)
        }
        return nil
    }
    /**
     从data获取 密钥
     - Parameters:
        - data: 密钥的源data
        - keyType: 密钥的类型
        - keySizeInBits: 密钥的大小
        - keyClass: 公钥 || 私钥
     - returns: 返回来自data的密钥
     */
    func getKeyWithData(_ data: CFData, _ keyType: CFString, _ keySizeInBits: size_t, _ keyClass: CFString) -> SecKey? {
        let parameters = [kSecAttrKeyType: keyType,
                        kSecAttrKeySizeInBits: keySizeInBits,
                        kSecAttrKeyClass : keyClass ] as [CFString : Any]
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(data, parameters as CFDictionary, &error) else {
            // 与 generateKeyPair 相同的顺序约束：先取描述 → 再消费引用 → 断言用布尔快照。
            // 之前把消费写在了取描述之前，导致传入空 / 非法 key 数据时访问已释放的 CFError 而崩溃。
            let tipsString = "\(error_string_get_secKey) \(String(describing: error))"
            let hasError = (error != nil)
            _ = error?.takeRetainedValue()
            assert(hasError, tipsString)
            errorTips(tips: tipsString)
            return nil
        }
        return secKey
        
    }
    
    /**
     从钥匙串中获取 密钥
    - Parameters:
        - query: 获取的参数
     - returns: 返回来自钥匙串的密钥
     */
    func getKeyWithKeychain(query: Dictionary<String, Any>) -> SecKey? {
        var key: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &key)
        guard status == errSecSuccess, let key = key else {
            errorTips(tips: error_get_keychain)
            return nil
        }
        // CFTypeRef → SecKey 不能写条件向下转换：CoreFoundation 类型不支持运行时类型检查，
        // 写成 `as?` 会直接编译报错（conditional downcast ... will always succeed），
        // 原实现用 `as!`（失败即崩溃）。此处沿用本文件既有的 Unmanaged 取回方式，
        // 并先用 CFTypeID 确认实际类型，因此不存在强解包也无崩溃路径。
        guard CFGetTypeID(key) == SecKeyGetTypeID() else {
            errorTips(tips: error_get_keychain)
            return nil
        }
        return Unmanaged<SecKey>.fromOpaque(Unmanaged.passUnretained(key).toOpaque()).takeUnretainedValue()
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
        if SecTrustCreateWithCertificates(cert, policy, &trust) == noErr, let trustRef = trust {
            // 用非弃用的 SecTrustEvaluateWithError 替换 iOS 13 起弃用的 SecTrustEvaluate（前者 iOS 12 起可用）。
            // 本方法的目的是「从 DER 证书取出公钥」，并不做信任链判定；
            // 因此语义与旧实现保持一致：评估结果不通过也照常取公钥（旧实现同样只看评估过程是否出错）。
            var trustError: CFError?
            if !SecTrustEvaluateWithError(trustRef, &trustError), let trustError = trustError {
                errorTips(tips: "\(error_public_secKey_null) \(trustError)")
            }
            key = _copyPublicKey(from: trustRef)
            return key
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
        let securityError = SecPKCS12Import(data as CFData, options, &items)
        guard securityError == noErr,
              let importItems = items,
              CFArrayGetCount(importItems) > 0 else {
            errorTips(tips: error_private_secKey_null)
            return nil
        }
        let appKey = Unmanaged.passUnretained(kSecImportItemIdentity).toOpaque()
        guard let identityDictRaw = CFArrayGetValueAtIndex(importItems, 0) else {
            errorTips(tips: error_private_secKey_null)
            return nil
        }
        let identityDict = Unmanaged<CFDictionary>.fromOpaque(identityDictRaw).takeUnretainedValue()
        guard let identityAppRaw = CFDictionaryGetValue(identityDict, appKey) else {
            errorTips(tips: error_private_secKey_null)
            return nil
        }
        let identityApp = Unmanaged<SecIdentity>.fromOpaque(identityAppRaw).takeUnretainedValue()
        guard SecIdentityCopyPrivateKey(identityApp, &key) == noErr else {
            errorTips(tips: error_private_secKey_null)
            return nil
        }
        return key
    }

    /// 取证书公钥：iOS 14 / macOS 11 起用 SecTrustCopyKey，更低版本回退到已弃用的 SecTrustCopyPublicKey
    private func _copyPublicKey(from trust: SecTrust) -> SecKey? {
        if #available(iOS 14.0, macOS 11.0, *) {
            return SecTrustCopyKey(trust)
        }
        return SecTrustCopyPublicKey(trust)
    }
}

