//
//  RSA.swift
//
//  Created by 韩增超 on 2022/10/18.
//
public struct RSA : AsymmetricType {
    // bits
    public enum RSAKeySize: Int {
        case size512 = 512   // 64 byte
        case size1024 = 1024 // 128 byte
        case size2048 = 2048 // 265 byte
        case size4096 = 4096 // 512 byte
    }
    // During encryption, you need to mix the data with the key, which has a fixed length of 11 bytes
    private let keyLength = 11
    // Encryption mode: Encryption mode provided by the system
    var rsaAlgorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
    // Create a private key and a public key
    var identifierString: String = "RSATest"
    // The encryption key setting requires the encryption size
    var keySize: RSAKeySize = .size1024
    // private key
    var privateSecKey: SecKey?
    // public key
    var publicSecKey: SecKey?
    // private key identifier
    private var privateKeyIdentifier: String?
    // public key identifier
    private var publicKeyIdentifier: String?
    // private key identifier data
    private var privateKeyTag: Data?
    // public key identifier data
    private var publicKeyTag: Data?
    
    /**
     - Parameters:
        - identifierString: if you need create privateKey & publicKey ||  you get key with string , save to keychain ，identifierString is the identity in keychain
        - keySize: key size , it's enum, key size, The length of encrypted data is affected
        - algorithm: system algorithm
        - default：identifierString = "RSATest", keySize = .size1024, algorithm .rsaEncryptionPKCS1
     */
   public init(identifierString: String = "RSATest", keySize: RSAKeySize = .size1024, algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1) {
        self.identifierString = identifierString
        self.keySize = keySize
        self.rsaAlgorithm = algorithm
        _setAttribute()
    }
    /** create privateKey & publicKey , save to keychain */
    public mutating func generateRSAKeyPair() {
        guard publicSecKey == nil else {
            return
        }
        if publicKeyTag == nil {
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
    public mutating func setPrivateSecKey(keyString: String? = nil, P12Path: String? = nil, P12Password: String? = "") {
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
    public mutating func setPublicSecKey(keyString: String? = nil, DERPath: String? = nil) {
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
    /** If publicKey exists , get public key to string */
    public func publicKeyString() -> String? {
        guard publicSecKey != nil else {
            return nil
        }
        return _secKeyToString(publicSecKey!)
    }
    /** If privateKey exists , get private key to string */
    public func privateKeyString() -> String? {
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
    public func secKeyToString(_ key: SecKey) -> String? {
        return _secKeyToString(key)
    }
    
    private func _secKeyToString(_ key: SecKey) -> String? {
        var error:Unmanaged<CFError>?
        if let cfdata = SecKeyCopyExternalRepresentation(key, &error) {
           let data:Data = cfdata as Data
           let b64Key = data.base64EncodedString()
           return b64Key
        }
        return nil
    }
    private mutating func _setAttribute() {
        privateKeyIdentifier = identifierString.appending(".privateKey")
        publicKeyIdentifier = identifierString.appending(".publicKey")
        privateKeyTag = privateKeyIdentifier!.data(using: .utf8)!
        publicKeyTag = publicKeyIdentifier!.data(using: .utf8)!
    }
    /** Get the public and private keys from the key string */
    private func _addKeyWithString(_ string: String, _ keyClass: CFString) -> SecKey? {
       return getKeyWithString(string, kSecAttrKeyTypeRSA, keySize.rawValue, keyClass)
    }
    /** This parameter is required when obtaining the public and private keys from the key string*/
    private func _getRSAKeyFromKeychain(isPrivate: CFString, keySize: size_t, ApplicationTag: Data, ApplicationLabel:  String) -> SecKey? {
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
    /** Set the parameters required to save the public and private keys*/
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

/** encrypt Decrypt*/
extension RSA {
    /** Process the original data before encryption and decryption*/
    private func _encryptDecryptPrepare(source: Data, key: SecKey?, defaultLength: Int) -> [Data]? {
        guard !source.isEmpty && key != nil else {
            if source.count > 0 {
                errorTips(tips: error_public_secKey_null)
                return nil
            }
            errorTips(tips: error_length)
            return nil
        }
        guard source.count > defaultLength else {
            return [source]
        }
        let sourceBytes = [UInt8](source)
        var sources:Array<Data> = []
        let res = dealListToNumSubList(list: sourceBytes, num: defaultLength)
        for itemData in res {
            sources.append(Data(bytes: itemData, count: itemData.count))
        }
        return sources
    }
     
    typealias ED_Func = (SecKey, SecKeyAlgorithm, CFData, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData?
    
    /** Methods of encryption and decryption */
    private func _encryptedDecryptedData(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ plaintext: CFData, _ edFunc:ED_Func) -> Data? {
        var error: Unmanaged<CFError>?
        let resData = edFunc(key, algorithm, plaintext, &error) as Data?
        guard error == nil else {
            errorTips(tips: "\(error_rsa_encrypt) \(String(describing: error))")
            return nil
        }
        return  resData
    }
    private func _encryptDecrypt(datas: [Data], key: SecKey, alg: SecKeyAlgorithm, edFunc: ED_Func) -> Data? {
        guard datas.count > 0 else {
            return nil
        }
        if datas.count == 1 {
            return _encryptedDecryptedData(key, alg, datas.first! as CFData, edFunc)
        }
        var res:Data = Data()
        for sourceData in datas {
            if let encryptedData = _encryptedDecryptedData(key, alg, sourceData as CFData, edFunc) {
                let bytes = [UInt8] (encryptedData)
                res.append(bytes, count:bytes.count)
            }
        }
        return res
    }
    
    private func _encrypt(source: Data) -> Data? {
        if let datas = _encryptDecryptPrepare(source: source, key: self.publicSecKey, defaultLength: keySize .rawValue / 8 - keyLength){
            return _encryptDecrypt(datas: datas, key:  self.publicSecKey!, alg: rsaAlgorithm, edFunc: SecKeyCreateEncryptedData)
        }
        return nil
    }
    private func _decrypt(source: Data) -> Data? {
        if let datas = _encryptDecryptPrepare(source: source, key: self.privateSecKey, defaultLength: keySize.rawValue / 8) {
            return _encryptDecrypt(datas: datas, key:  self.privateSecKey!, alg: rsaAlgorithm, edFunc: SecKeyCreateDecryptedData)
        }
       return nil
    }
}

/** EncryptDecryptType protocol method */
extension RSA {
    public func encrypt(_ sourceData: Data) -> Data {
        if let data = _encrypt(source: sourceData){
            return data
        }
        return Data()
    }
    
    public func decrypt(_ sourceData: Data) -> Data {
        if let data = _decrypt(source: sourceData){
            return data
        }
        return Data()
    }
}
