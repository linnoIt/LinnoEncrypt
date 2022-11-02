//
//  HMAC.swift
//  EncryptDecrypt
//
//  Created by 韩增超 on 2022/10/28.
//

import Foundation
// 支持iOS13及以上
import CryptoKit
// 支持iOS13以下
import CommonCrypto.CommonHMAC
/**它通过一个标准算法，在计算哈希的过程中，把key混入计算过程中。**/
final public class H_MAC:HashType {

    public enum H_MAC_hashType{
        case SHA1
        case SHA256
        case SHA384
        case SHA512
        case MD5
        
        var HMACAlgorithm: CCHmacAlgorithm {
             var result: Int = 0
             switch self {
             case .MD5:      result = kCCHmacAlgMD5
             case .SHA1:     result = kCCHmacAlgSHA1
             case .SHA256:   result = kCCHmacAlgSHA256
             case .SHA384:   result = kCCHmacAlgSHA384
             case .SHA512:   result = kCCHmacAlgSHA512
                 
             }
             return CCHmacAlgorithm(result)
         }
          
         var digestLength: Int {
             var result: Int32 = 0
             switch self {
             case .MD5:      result = CC_MD5_DIGEST_LENGTH
             case .SHA1:     result = CC_SHA1_DIGEST_LENGTH
             case .SHA256:   result = CC_SHA256_DIGEST_LENGTH
             case .SHA384:   result = CC_SHA384_DIGEST_LENGTH
             case .SHA512:   result = CC_SHA512_DIGEST_LENGTH
                 
             }
             return Int(result)
         }
    }
    /**
     SymmetricKey iOS13后使用
     */
    private var macKey:Any?
    
    private var hashType:Any?
    
    init(key: String = "testKey", type:H_MAC_hashType = .SHA256 ) {
        _setHashType(type: type)
        _setmacKey(source: key)
    }
    
    func hashString(sourceString: String) -> String {
        var resString:String
        if #available(iOS 13.0, *) {
            resString = _HMACEncrypt13(source: sourceString)
        } else {
            resString = _HMACEncrypt(source: sourceString, algorithm: hashType as! H_MAC.H_MAC_hashType, key: macKey as! String)
        }
        return resString
    }
    
    private  func _setHashType(type:H_MAC_hashType) {
        if #available(iOS 13.0, *) {
            switch type {
            case .SHA1:
                hashType = Insecure.SHA1()
            case .SHA256:
                hashType = SHA256()
            case .SHA384:
                hashType = SHA384()
            case .SHA512:
                hashType = SHA512()
            case .MD5:
                hashType = Insecure.MD5()
            }
        } else {
            hashType = type
            // Fallback on earlier versions
        }
    }
    
    private  func _setmacKey(source:String) {
        if #available(iOS 13.0, *) {
            guard (source.count > 0) else {
                macKey = SymmetricKey(size: .bits192)
                return
            }
            if let data = source.data(using: .utf8){
                macKey = SymmetricKey(data: data)
            }
        } else {
            macKey = source
            // Fallback on earlier versions
        }
    }

    private func _HMACEncrypt(source: String, algorithm: H_MAC_hashType, key:String) -> String{
        if let useStr = source.cString(using: .utf8){
            let useStrlength = Int(source.lengthOfBytes(using: .utf8))
            let digestlength = algorithm.digestLength
            let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestlength)
            if let useKey = key.cString(using:.utf8){
                let useKeyLength = Int(key.lengthOfBytes(using:.utf8))
                
                CCHmac(algorithm.HMACAlgorithm, useKey, useKeyLength, useStr, useStrlength, result)
                let digest = _stringFromResult(result: result, length: digestlength)
                
                result.deallocate()
                return digest
            }
            errorTips(tips: error_H_MAC_key_error)
        }
        errorTips(tips: error_H_MAC_source_error)
        return source
    }

    private func _stringFromResult(result: UnsafeMutablePointer<CUnsignedChar>,
                                  length: Int) -> String {
        let hash = NSMutableString()
        for i in 0..<length {
            hash.appendFormat("%02x", result[i])
        }
        return String(hash)
    }
}


@available(iOS 13.0, *)
extension H_MAC{
    private  func _HMACEncrypt13(source: String) -> String{
        let type:any HashFunction = hashType as! any HashFunction
        if let data = source.data(using: .utf8){
            return _HMAC_Hash(data: data, key: macKey as! SymmetricKey, hashClass: type)
        }
        errorTips(tips: error_H_MAC_source_error)

        return source
    }
    private func _HMAC_Hash<T:HashFunction>(data:Data, key:SymmetricKey, hashClass:T) -> String {
        let res = HMAC<T>.authenticationCode(for: data, using: key)
        if let deRange = res.description.range(of: ": "){
            return String(res.description.suffix(from: deRange.upperBound))
        }
        errorTips(tips: error_H_MAC_system_error)
        return ""
    }
    
    
    
    
    
    
    
    /// 未完成
    @available(iOS 13.2, *)
    private func _isValid<T:HashFunction>(data:Data,message:Data, key:SymmetricKey, type:T ) -> Bool {
//        HMAC<T>.isValidAuthenticationCode(<#T##mac: HashedAuthenticationCode<HashFunction>##HashedAuthenticationCode<HashFunction>#>, authenticating: <#T##UnsafeRawBufferPointer#>, using: <#T##SymmetricKey#>)
        
//        HMAC<T>.isValidAuthenticationCode(<#T##authenticationCode: ContiguousBytes##ContiguousBytes#>, authenticating: <#T##DataProtocol#>, using: <#T##SymmetricKey#>)
        
        
//        if HMAC<T>.isValidAuthenticationCode(data,
//           authenticating: data, using: key) {
//            print("The message authentication code is validating the data: \(data))")
//            return true
//        }
//        else { print("not valid") }
        return false
    }
    
    @available(iOS 13.2, *)
    private func isValidAuthentication(data:Data,message:Data) -> Bool{
        let type:any HashFunction = hashType as! any HashFunction
        return _isValid(data: data, message: message, key: macKey as! SymmetricKey, type: type)
    }
}
