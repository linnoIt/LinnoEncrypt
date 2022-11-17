//
//  Sha.swift
//
//  Created by 韩增超 on 2022/10/17.
//

import CryptoKit
import CommonCrypto

struct Sha : HashType {
    
    public enum hashValue {
        /** sha256*/
        case hash256
        /** sha384*/
        case hash384
        /** sha512*/
        case hash512
        /** sha1 ⚠️⚠️⚠️不安全的 散列方式，不建议使用*/
        case hash1
    }
    // 具体hash的方法
    typealias cc_type = (UnsafeRawPointer?, CC_LONG,  UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>?

    /**协议实现默认采用Sha 256的散列方法 */
    public func hashString(sourceString: String) -> String {
         hashString(sourceString: sourceString, hashType: .hash256)
    }
    /**
     带有选择散列类型的的散列方法
     - Parameters:
        - sourceString :专有的key
        - hashType: hash的类型
     - returns   : hash后的数据
     */
    public func hashString(sourceString: String, hashType: hashValue) -> String {
        assert(sourceString.count > 0,error_length)
        guard sourceString.count > 0 else {
            errorTips(tips: error_length)
           return error_length
        }
        let hashData = sourceString.data(using: .utf8)!
        if #available(iOS 13.0, *) {
            var sha:any HashFunction
            switch hashType {
            case .hash256:
                sha = SHA256()
            case .hash384:
                sha = SHA384()
            case .hash512:
                sha = SHA512()
            case .hash1:
                sha = Insecure.SHA1()
            }
            return _hash(hashData: hashData, hashClass: sha)
        } else {
            var digest_length:Int32
            var ccFunc:cc_type
            switch hashType {
            case .hash256: digest_length = CC_SHA256_DIGEST_LENGTH
                ccFunc = CC_SHA256
            case .hash384: digest_length = CC_SHA384_DIGEST_LENGTH
                ccFunc = CC_SHA384
            case .hash512: digest_length = CC_SHA512_DIGEST_LENGTH
                ccFunc = CC_SHA512
            case .hash1:digest_length = CC_SHA1_DIGEST_LENGTH
                    ccFunc = CC_SHA1
            }
            return _shaHash(hashData: hashData, digest_length: digest_length, ccFunc: ccFunc)
            // Fallback on earlier versions
        }
    }
    /**
     兼容 iOS 13 以下，带有选择散列类型的的散列方法
     - parameters:
        - hashData :hash的数据
        - digest_length: 数据长度
        - ccFunc: hash的具体方法
     - returns   : hash后的数据
     */
    private func _shaHash(hashData: Data, digest_length: Int32, ccFunc: cc_type) -> String {
        var digest = [UInt8](repeating: 0, count: Int(digest_length))
        hashData.withUnsafeBytes {
            bytes in
            _ = ccFunc(bytes.baseAddress,CC_LONG(hashData.count),&digest)
        }
        return digest.reduce("") { $0 + String(format:"%02x", $1) }
    }
}

