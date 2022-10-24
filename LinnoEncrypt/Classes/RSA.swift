//
//  RSA.swift
//  QR
//
//  Created by 韩增超 on 2022/10/18.
//

import Foundation

public struct RSA: AsymmetricType{
    
    public enum RSAKeySize: Int {
        case size512 = 512
        case size768 = 768
        case size1024 = 1024
        case size2048 = 2048
    }
    
    var rsaAlgorithm:SecKeyAlgorithm = .rsaEncryptionPKCS1
    
    var identifierString: String = "RSATest"
    
    var keySize: RSAKeySize = .size1024
    
    var privateSecKey: SecKey?
    
    var publicSecKey: SecKey?
    
    private var privateKeyIdentifier: String?
    
    private var publicKeyIdentifier: String?
    
    private var privateKeyTag: Data?
    
    private var publicKeyTag: Data?
    
    /**
     - Parameters:
        - identifierString: if you need create privateKey & publicKey ||  you get key with string , save to keychain ，identifierString is the identity in keychain
        - keySize: key size , it's enum
        - algorithm: key type
        - default：identifierString = "RSATest", keySize = .size1024, algorithm .rsaEncryptionPKCS1
     */
   public init(identifierString: String = "RSATest", keySize:RSAKeySize = .size1024, algorithm:SecKeyAlgorithm = .rsaEncryptionPKCS1) {
        self.identifierString = identifierString
        self.keySize = keySize
        self.rsaAlgorithm = algorithm
        _setAttribute()
    }
    /** create privateKey & publicKey , save to keychain */
    public mutating func generateRSAKeyPair(){
        guard publicSecKey == nil else {
            return
        }
        if publicKeyTag == nil{
            _setAttribute()
        }
        let keyTuple = generateKeyPair(keySize: keySize.rawValue, keyType: kSecAttrKeyTypeRSA)
        privateSecKey = keyTuple?.0
        publicSecKey =  keyTuple?.1
        _saveRSAKeyToKeychain(key: publicSecKey!, keySize: keySize.rawValue, isPrivate: false)
        _saveRSAKeyToKeychain(key: privateSecKey!, keySize: keySize.rawValue, isPrivate: true)
    }
    
    /**
     set privateKey
     - Parameters:
        - keyString: get with string
        - P12Path: get with p12 certificate path
        - password: p12 certificate password
        - default： get with keychain
     */
    public mutating func setPrivateSecKey(keyString:String? = nil, P12Path:String? = nil, P12Password:String? = ""){
        guard keyString == nil else {
            privateSecKey = _addKeyWithString(keyString!,kSecAttrKeyClassPrivate)
            return
        }
        guard P12Path == nil else {
            privateSecKey = getPrivateKeyWithP12(P12Path! ,with: P12Password)
            return
        }
        privateSecKey = _getRSAKeyFromKeychain(isPrivate: kSecAttrKeyClassPrivate, keySize: keySize.rawValue, ApplicationTag: privateKeyTag!, ApplicationLabel: privateKeyIdentifier!)
    }
    /**
     set publicKey
     - Parameters:
        - keyString: get with string
        - DERPath: get with DER certificate path
        - default：get with keychain
     */
    public mutating func setPublicSecKey(keyString:String? = nil, DERPath:String? = nil){
        guard keyString == nil else {
            publicSecKey = _addKeyWithString(keyString!,kSecAttrKeyClassPublic)
            return
        }
        guard DERPath == nil else {
            publicSecKey = getPublicKeywithDER(DERPath!)
            return
        }
        publicSecKey = _getRSAKeyFromKeychain(isPrivate: kSecAttrKeyClassPublic, keySize: keySize.rawValue, ApplicationTag: publicKeyTag!, ApplicationLabel: publicKeyIdentifier!)
    }
    /** set privateKey & publicKey , default get with keychain */
    public  mutating func setRSAKey(){
        _setAttribute()
        setPublicSecKey()
        setPrivateSecKey()
    }
    /** If publicKey exists , get public key to string */
    public func publicKeyString() -> String?{
        guard publicSecKey != nil else {
            return nil
        }
        return _secKeyToString(publicSecKey!)
    }
    /** If privateKey exists , get private key to string */
    public func privateKeyString() -> String?{
        guard privateSecKey != nil else {
            return nil
        }
        return _secKeyToString(privateSecKey!)
    }
    /**
     - Parameters:
        - key: secret key
     - returns: string with secret key
     */
    public func secKeyToString(_ key:SecKey) -> String? {
        return _secKeyToString(key)
    }
    
    private mutating func _setAttribute(){
        privateKeyIdentifier = identifierString.appending(".privateKey")
        publicKeyIdentifier = identifierString.appending(".publicKey")
        privateKeyTag = privateKeyIdentifier!.data(using: .utf8)!
        publicKeyTag = publicKeyIdentifier!.data(using: .utf8)!
    }
    
    private func _secKeyToString(_ key:SecKey) -> String? {
        var error:Unmanaged<CFError>?
        if let cfdata = SecKeyCopyExternalRepresentation(key, &error) {
           let data:Data = cfdata as Data
           let b64Key = data.base64EncodedString()
            return b64Key
        }
        return nil
    }
    /** 根据密钥字符串获取获取公钥和私钥*/
    private func _addKeyWithString(_ string:String, _ keyClass: CFString) -> SecKey? {
       return getKeyWithWithString(string, kSecAttrKeyTypeRSA, keySize.rawValue, keyClass)
    }
    /** 根据identifierString从钥匙串中获取公钥和私钥*/
    private func _getRSAKeyFromKeychain(isPrivate:CFString, keySize: size_t, ApplicationTag:Data, ApplicationLabel: String) -> SecKey? {
        var queryDictionary = [String: Any]()
        queryDictionary[kSecClass as String] = kSecClassKey
        queryDictionary[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        queryDictionary[kSecAttrApplicationTag as String] = ApplicationTag
        queryDictionary[kSecAttrKeyClass as String] = isPrivate
        queryDictionary[kSecReturnRef as String] = kCFBooleanTrue
        queryDictionary[kSecAttrApplicationLabel as String] =  ApplicationLabel
        queryDictionary[kSecAttrKeySizeInBits as String] = keySize
        return getKeyWithKeychain(query: queryDictionary)
    }
    /** 保存 公钥和私钥的值*/
    private func _saveRSAKeyToKeychain(key: SecKey, keySize: size_t, isPrivate: Bool) {
        var saveDictionary = [String: Any]()
        let keyClass = isPrivate ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic
        saveDictionary[kSecClass as String] = kSecClassKey
        saveDictionary[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        saveDictionary[kSecAttrApplicationTag as String] = isPrivate ? privateKeyTag : publicKeyTag
        saveDictionary[kSecAttrKeyClass as String] = keyClass
        saveDictionary[kSecValueData as String] = getKeyDataFrom(secKey: key, tag: (isPrivate ? privateKeyTag : publicKeyTag)!, keyType: kSecAttrKeyTypeRSA)
        saveDictionary[kSecAttrKeySizeInBits as String] = keySize
        saveDictionary[kSecAttrEffectiveKeySize as String] = SecKeyGetBlockSize(key)
        saveDictionary[kSecAttrCanDerive as String] = kCFBooleanFalse
        saveDictionary[kSecAttrCanEncrypt as String] = kCFBooleanTrue
        saveDictionary[kSecAttrCanDecrypt as String] = kCFBooleanTrue
        saveDictionary[kSecAttrCanVerify as String] = kCFBooleanTrue
        saveDictionary[kSecAttrCanSign as String] = kCFBooleanFalse
        saveDictionary[kSecAttrCanWrap as String] = kCFBooleanTrue
        saveDictionary[kSecAttrCanUnwrap as String] = kCFBooleanFalse
        saveDictionary[kSecAttrApplicationLabel as String] = isPrivate ? privateKeyIdentifier : publicKeyIdentifier
        saveKeyToKeychain(query: saveDictionary)
    }
}

extension RSA{
    public func encrypt(_ source: String) -> String {
        guard !source.isEmpty && self.publicSecKey != nil else {
            assert(source.count > 0,error_length)
            assert(self.publicSecKey != nil,error_publicSecKey_null)
            return source
        }
        let data = source.data(using: String.Encoding.utf8)!
        var error: Unmanaged<CFError>?
        let resData = SecKeyCreateEncryptedData(self.publicSecKey!, rsaAlgorithm, data as CFData, &error) as Data?
        return  resData!.base64EncodedString(options: .lineLength64Characters)
    }
    public func decrypt(_ source: String) -> String {
        guard !source.isEmpty && self.privateSecKey != nil else {
            assert(source.count > 0,error_length)
            assert(self.privateSecKey != nil,error_privateSecKey_null)
            return source
        }
        let data = Data(base64Encoded: source, options: .ignoreUnknownCharacters)
        var error: Unmanaged<CFError>?
        let resData =  SecKeyCreateDecryptedData(self.privateSecKey!, rsaAlgorithm, data! as CFData, &error) as Data?
        return String(data: resData!, encoding: String.Encoding.utf8)!
    }
}
