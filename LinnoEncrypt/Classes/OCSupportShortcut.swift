//
//  OCSupportShortcut.swift
//  EncryptDecrypt
//
//  Created by 韩增超 on 2022/11/7.
//

/// hash字符串支持oc使用
final public class OCSupportShortcut_Hash : NSObject {
    
    @objc public enum hashType: Int {
        case md5, sha1, sha256, sha384, sha512
        var type: H_MAC.H_MAC_hashType {
            var result: H_MAC.H_MAC_hashType
             switch self {
                 case .md5:      result = .MD5
                 case .sha1:     result = .SHA1
                 case .sha256:   result = .SHA256
                 case .sha384:   result = .SHA384
                 case .sha512:   result = .SHA512
             }
             return result
         }
    }
    /// 五种hash
    @objc public static func hashString(source: String, type: hashType ) -> String {
        let res: String
        switch type {
            case .md5:
                res = source.hashString.md5
            case .sha1:
                res = source.hashString.sha1
            case .sha256:
                res = source.hashString.sha256
            case .sha384:
                res = source.hashString.sha384
            case .sha512:
                res = source.hashString.sha512
        }
        return res
    }
    /// HMAC
    @objc public static func hmacString(source: String, key: String ,type: hashType) -> String {
        return source.hashString.hmac(key: key, type:type.type )
    }
}

/// RSA支持oc使用
final public class OCSupportShortcut_RSA : NSObject {

    @objc public enum KeySize: Int {
        case size512, size1024, size2048, size4096
        var useRSASize: RSA.RSAKeySize {
            var res = RSA.RSAKeySize.size1024
            switch self {
            case .size512:
                res = RSA.RSAKeySize.size512
            case .size1024:
                res = RSA.RSAKeySize.size1024
            case .size2048:
                res =  RSA.RSAKeySize.size2048
            case .size4096:
                res = RSA.RSAKeySize.size4096
            }
            return res
        }
    }
    
    var rsa:RSA?
    
    @objc public convenience init(identifierString: String = "RSATest", keySize: KeySize = .size1024, algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1) {
        self.init()
        rsa = RSA(identifierString: identifierString, keySize: keySize.useRSASize, algorithm: algorithm)
     }
    @objc public convenience init(publicKeyString: String?, privateKeyString: String?) {
        self.init()
        rsa = RSA()
        if publicKeyString != nil {
            rsa?.setPublicSecKey(keyString: publicKeyString)
        }
        if privateKeyString != nil {
            rsa?.setPrivateSecKey(keyString: privateKeyString)
        }
     }
    @objc public convenience init(publicKeyPath: String?, privateKeyPath: String?) {
        self.init()
        rsa = RSA()
        if publicKeyPath != nil {
            rsa?.setPublicSecKey(DERPath: publicKeyPath)
        }
        if privateKeyPath != nil {
            rsa?.setPrivateSecKey(P12Path: privateKeyPath)
        }
     }
    
    @objc public func encryptString(source: String) -> String {
        rsa!.encrypt(sourceString: source)
    }
    @objc public func encryptArray(source: Array<Any>)-> String {
        rsa!.encrypt(sourceArray: source) ?? ""
    }
    @objc public func encryptDictionary(source: Dictionary<String, Any>)-> String {
        rsa!.encrypt(sourceDictionary: source) ?? ""
    }
    @objc public func decryptToString(source: String) -> String {
        rsa!.decrypt(sourceString: source)
    }
    
    @objc public func decryptToArray(source: String) -> Array<Any> {
        if let res:Array<Any> = rsa!.decrypt(sourceString: source) {
            return res
        }
        return []
    }
    
    @objc public func decryptToDictionary(source: String) -> Dictionary<String, Any> {
        if let res:Dictionary<String, Any> = rsa!.decrypt(sourceString: source){
            return res
        }
        return [:]
    }
    
    @objc public func getPublicKeyString() -> String? {
       rsa?.publicKeyString()
    }
    
    @objc public func getPrivateKeyString() -> String? {
        rsa?.privateKeyString()
    }

    private override init() {
        super.init()
    }
}


/// 对称加密支持oc使用 （不包含AES-GCM ）
final public class OCSupportShortcut_Symmetric : NSObject {
    
    @objc public enum encryptMode: Int {
        case DES, _3DES, AES128, AES192, AES256, CAST, RC4, RC2, Blowfish, ChaCha20
    }
    private var keySize: otherEncry.KeyLength = .minSize
    
    private var authenticating: String?
    
    private var modeClass: SymmetricEncryptDecryptProducer = SymmetricEncryptDecryptProducer()
    
    @objc public convenience init(key: String ,mode: encryptMode = .DES, keySizeBig: Bool = false ) {
        self.init()
        if keySizeBig {
            keySize = .maxSize
        }
        _setAttribute(mode: mode, key: key)
    }

    @objc public convenience init(key: String, ChaCha20Authenticating: String ) {
        self.init()
        authenticating = ChaCha20Authenticating
        _setAttribute(mode: .ChaCha20, key: key)
    }
    
    @objc public convenience init(key: String ,mode: encryptMode ) {
        self.init()
        _setAttribute(mode: mode,key: key)
    }
    
    private override init() {
        super.init()
    }
    
    private func _setAttribute(mode: encryptMode, key: String) {
        switch mode {
            case .DES:
                modeClass = DES(key: key)
            case ._3DES:
                modeClass = _3DES(key: key)
            case .AES128:
                modeClass = AES(key: key,keySize: .AES128)
            case .AES192:
                modeClass = AES(key: key,keySize: .AES192)
            case .AES256:
                modeClass = AES(key: key,keySize: .AES256)
            case .CAST:
                modeClass = otherEncry(key: key,encryption: .CAST, keySize: keySize)
            case .RC4:
                modeClass = otherEncry(key: key,encryption: .RC4, keySize: keySize)
            case .RC2:
                modeClass = otherEncry(key: key,encryption: .RC2, keySize: keySize)
            case .Blowfish:
                modeClass = otherEncry(key: key,encryption: .Blowfish, keySize: keySize)
            case .ChaCha20:
                modeClass = ChaCha20(key: key, authenticating: authenticating)
        }
    }
    // 加密
    @objc public func encrypt(source: Data)-> Data {
        return  modeClass.encrypt(source)
    }
    @objc public func encryptData(source: Data) -> String {
        return  modeClass.encrypt(sourceData: source)
    }
    @objc public func encryptString(source: String) -> String {
        return  modeClass.encrypt(sourceString: source)
    }
    @objc public func encryptArray(source: Array<Any>)-> String {
        return  modeClass.encrypt(sourceArray: source) ?? ""
    }
    @objc public func encryptDictionary(source: Dictionary<String, Any>)-> String {
        return  modeClass.encrypt(sourceDictionary: source) ?? ""
    }
    // 解密
    @objc public func decryptToData(source: String) -> Data {
        return modeClass.decrypt(sourceString: source)
    }
    @objc public func decryptToString(source: String) -> String {
        return modeClass.decrypt(sourceString: source)
    }
    
    @objc public func decryptToArray(source: String) -> Array<Any> {
        if let res:Array<Any> = modeClass.decrypt(sourceString: source) {
            return res
        }
        return []
    }
    
    @objc public func decryptToDictionary(source: String) -> Dictionary<String, Any> {
        if let res:Dictionary<String, Any> = modeClass.decrypt(sourceString: source){
            return res
        }
        return [:]
    }
}
