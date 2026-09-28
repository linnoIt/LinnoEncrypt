//
//  HMAC.swift
//  EncryptDecrypt
//
//  Created by 韩增超 on 2022/10/28.
//

// 支持iOS13及以上
import CryptoKit
// 支持iOS13以下（用伞模块：CCHmac 来自 CommonHMAC，CC_*_DIGEST_LENGTH 来自 CommonDigest）
import CommonCrypto
import Foundation
/**它通过一个标准算法，在计算哈希的过程中，把key混入计算过程中。**/
final public class H_MAC : HashType {

    /** HMAC的hash类型枚举 */
    public enum H_MAC_hashType: CaseIterable {
        case SHA1
        case SHA256
        case SHA384
        case SHA512
        case MD5
        /** hash类型  转换（iOS 13 以下 CommonCrypto 通道使用）*/
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
        /** 该算法输出的摘要字节数（0.2.0 起对外可见）*/
         public var digestLength: Int {
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

    /** HMAC 结果的输出格式（0.2.0 新增）*/
    public enum H_MAC_outputFormat {
        /** 16 进制小写：与既有 hashString(sourceString:) 的输出一致 */
        case hexLowercase
        /** 16 进制大写 */
        case hexUppercase
        /** Base64 */
        case base64
    }

    /// 密钥统一保存为原始字节：String 按 UTF-8 编码后，
    /// CryptoKit（iOS 13+）与 CommonCrypto（iOS 13 以下）两条通道处理的字节序列完全一致
    private var macKey: Data?
    /// hash 的类型（不再经 Any 间接存储）
    private var hashType: H_MAC_hashType?

    /**
     - Parameters:
        - key: 密钥。默认空串：未显式提供密钥时不再回退到弱默认值，也不再静默生成随机密钥
               （后者会让同一输入每次得到不同的 MAC，结果无法复现），而是由计算入口显式报错。
        - type:hash type
     */
    public init(key: String = "", type: H_MAC_hashType = .SHA256 ) {
        _setHashType(type: type)
        _setmacKey(source: key)
    }

    /** 该实例所用算法输出的摘要字节数（未显式指定算法时为 0，0.2.0 新增）*/
    public var digestLength: Int {
        hashType?.digestLength ?? 0
    }

    // MARK: - 0.2.0 新增 · 更换密钥

    /** 用文本密钥替换当前密钥（与 SymmetricEncryptDecryptProducer.replacekey 同名同义）*/
    public func replacekey(key: String) {
        _setmacKey(source: key)
    }

    /** 用原始字节密钥替换当前密钥（适用于二进制密钥、PBKDF2 等派生密钥）；空 Data 视为未设置密钥*/
    public func replacekey(data: Data) {
        guard !data.isEmpty else {
            macKey = nil
            errorTips(tips: error_H_MAC_key_error)
            return
        }
        macKey = data
    }

    /** 用 SymmetricKey 替换当前密钥*/
    @available(iOS 13.0, *)
    public func replacekey(symmetricKey: SymmetricKey) {
        macKey = symmetricKey.withUnsafeBytes { Data($0) }
    }

    // MARK: - 0.2.0 新增 · 计算

    /** 原始字节输出：String 输入按 UTF-8 编码后计算*/
    public func hashData(sourceString: String) -> Data {
        guard let data = sourceString.data(using: .utf8) else {
            errorTips(tips: tips_data_type_error)
            assertionFailure(tips_data_type_error)
            return Data()
        }
        return _authenticationCode(for: data)
    }

    /** 原始字节输出：原始字节输入，不做任何编码转换（适用于二进制数据）*/
    public func hashData(data: Data) -> Data {
        _authenticationCode(for: data)
    }

    /** 按指定格式输出：String 输入*/
    public func hashString(sourceString: String, format: H_MAC_outputFormat) -> String {
        _format(hashData(sourceString: sourceString), format: format)
    }

    /** 按指定格式输出：原始字节输入*/
    public func hashString(data: Data, format: H_MAC_outputFormat = .hexLowercase) -> String {
        _format(_authenticationCode(for: data), format: format)
    }

    /**
     校验 MAC 是否与当前密钥下的期望值一致。
     采用按位异或累加的恒定时间比较（无提前退出），长度不符直接返回 false。
     */
    public func isValid(mac: Data, for data: Data) -> Bool {
        let expected = _authenticationCode(for: data)
        guard !expected.isEmpty, expected.count == mac.count else { return false }
        var diff: UInt8 = 0
        for index in 0..<expected.count {
            diff |= expected[index] ^ mac[index]
        }
        return diff == 0
    }

    /** 校验字符串形式的 MAC（格式由 format 指定；字符串无法解析时返回 false）*/
    public func isValid(macString: String, format: H_MAC_outputFormat, for data: Data) -> Bool {
        guard let mac = _macData(from: macString, format: format) else { return false }
        return isValid(mac: mac, for: data)
    }

    /** 校验字符串形式的 MAC（便捷入口：String 输入 + 16 进制小写 MAC，与服务端常见返回格式对齐）*/
    public func isValid(macString: String, for sourceString: String) -> Bool {
        guard let data = sourceString.data(using: .utf8) else { return false }
        return isValid(macString: macString, format: .hexLowercase, for: data)
    }

    /** 一次性静态便捷方法：免构造实例（空 key 按约定 Debug 断言 / Release 返回空串）*/
    public static func hmac(data: Data, key: Data,
                            type: H_MAC_hashType = .SHA256,
                            format: H_MAC_outputFormat = .hexLowercase) -> String {
        guard !key.isEmpty else {
            errorTips(tips: error_H_MAC_key_error)
            assertionFailure(error_H_MAC_key_error)
            return ""
        }
        let mac = H_MAC(type: type)
        mac.replacekey(data: key)
        return mac.hashString(data: data, format: format)
    }

    // MARK: - 协议实现（既有公开入口，输出与 0.1.9 逐字符一致）

    public func hashString(sourceString: String) -> String {
        hashString(sourceString: sourceString, format: .hexLowercase)
    }

    // MARK: - 私有实现

    private func _setHashType(type: H_MAC_hashType) {
        hashType = type
    }

    /** 设置HMAC的key：空 key 置空，由计算入口显式报错 */
    private func _setmacKey(source: String) {
        guard !source.isEmpty else {
            macKey = nil
            return
        }
        macKey = Data(source.utf8)
    }

    /** 核心计算：统一两条系统通道，返回原始 MAC 字节；key 未设置 / 类型缺失时报错并返回空*/
    private func _authenticationCode(for data: Data) -> Data {
        guard let macKey = macKey, let type = hashType else {
            errorTips(tips: error_H_MAC_key_error)
            assertionFailure(error_H_MAC_key_error)
            return Data()
        }
        if #available(iOS 13.0, *) {
            let key = SymmetricKey(data: macKey)
            switch type {
            case .SHA1:   return _ckMAC(Insecure.SHA1.self, data: data, key: key)
            case .SHA256: return _ckMAC(SHA256.self, data: data, key: key)
            case .SHA384: return _ckMAC(SHA384.self, data: data, key: key)
            case .SHA512: return _ckMAC(SHA512.self, data: data, key: key)
            case .MD5:    return _ckMAC(Insecure.MD5.self, data: data, key: key)
            }
        }
        return _ccAuthenticationCode(for: data, type: type, key: macKey)
    }

    /** CryptoKit 通道（iOS 13+）：直接取原始字节，不再解析系统 description */
    @available(iOS 13.0, *)
    private func _ckMAC<T: HashFunction>(_ hashType: T.Type, data: Data, key: SymmetricKey) -> Data {
        HMAC<T>.authenticationCode(for: data, using: key).withUnsafeBytes { Data($0) }
    }

    /** CommonCrypto 通道（iOS 13 以下）*/
    private func _ccAuthenticationCode(for data: Data, type: H_MAC_hashType, key: Data) -> Data {
        var result = [UInt8](repeating: 0, count: type.digestLength)
        // 空 Data 的 baseAddress 为 nil。CCHmac 的 key/data 形参本身是可空指针，
        // 长度为 0 时不会解引用，直接传 nil 是安全的（已用空 key / 空 data / 双空三组对照验证），
        // 因此不再需要「用非空占位地址兜底」的强制解包写法。
        data.withUnsafeBytes { dataBytes in
            key.withUnsafeBytes { keyBytes in
                CCHmac(type.HMACAlgorithm,
                       keyBytes.baseAddress, key.count,
                       dataBytes.baseAddress, data.count,
                       &result)
            }
        }
        return Data(result)
    }

    /** 原始字节 → 指定格式字符串*/
    private func _format(_ code: Data, format: H_MAC_outputFormat) -> String {
        switch format {
        case .hexLowercase:
            return code.map { String(format: "%02x", $0) }.joined()
        case .hexUppercase:
            return code.map { String(format: "%02X", $0) }.joined()
        case .base64:
            return code.base64EncodedString()
        }
    }

    /** 字符串形式的 MAC → 原始字节；无法解析时返回 nil*/
    private func _macData(from string: String, format: H_MAC_outputFormat) -> Data? {
        switch format {
        case .base64:
            return Data(base64Encoded: string)
        case .hexLowercase, .hexUppercase:
            return string.hexadecimal()
        }
    }
}
