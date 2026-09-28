//
//  File.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import CommonCrypto
import Foundation

/**
 对称加密的工作模式。

 - `.ecb`：兼容模式。与 0.1.9 及更早版本的密文格式完全一致（ECB + PKCS7Padding，不使用 IV），
   存量数据可继续解密。
 - `.cbc(iv:)`：CBC 模式，支持两种 IV 归属方式：
    - `iv` 传 `nil`：自动生成密码学安全的随机 IV，并把 IV 前置拼接在密文头部（解密时自动取出），
      调用方无需自行管理 IV。
    - `iv` 传具体数据：使用调用方提供的 IV，长度必须等于算法的分组长度
      （AES 为 16 字节；DES / 3DES / CAST / RC2 / Blowfish 为 8 字节）。
 */
public enum SymmetricCipherMode {
    /// 兼容模式：ECB + PKCS7Padding，无 IV（与旧版本密文一致）
    case ecb
    /// CBC 模式；iv 传 nil 表示自动生成随机 IV 并前置到密文中
    case cbc(iv: Data?)
}

public class SymmetricEncryptDecryptProducer : SymmetricEncryptionBase {
    private let makeUpKey = "The padding string is automatica"
    /// 子类使用的文本密钥。默认空串：未显式设置密钥时不再回退到弱默认值，而是直接报错
    var testKey = ""

    public override func encrypt(_ sourceData: Data) -> Data {
        _EDRun(data: sourceData, kState: .kEncrypt)
    }
    
    public override func decrypt(_ sourceData: Data) -> Data {
        _EDRun(data: sourceData, kState: .kDecrypt)
    }
    
    /** 对称加密的工作模式，默认 .ecb（与旧版本密文兼容） */
    public var cipherMode: SymmetricCipherMode = .ecb
    
    /** 切换工作模式 */
    public func replaceCipherMode(_ mode: SymmetricCipherMode) {
        cipherMode = mode
    }
    
    /**
     子类是否依赖 `testKey` 作为密钥来源。
     自带密钥体系的子类（如 AES_GCM 使用 SymmetricKey）应覆盖为 false，
     避免被"key 未设置"校验拦截。
     */
    var usesTextKey: Bool { return true }
    
    private func _EDRun(data: Data, kState: kEncryptDecrypt) -> Data {
        guard data.count > 0 else {
            errorTips(tips: error_length)
            return Data()
        }
        if usesTextKey {
            guard !testKey.isEmpty else {
                errorTips(tips: error_key_not_set)
                assertionFailure(error_key_not_set)
                return Data()
            }
        }
        if let resData = runEncryptDecrypt(data: data, kState: kState) {
            return resData
        }
        errorTips(tips: error_encrypt_decrypt)
        return Data()
    }
    /** 修改加密的key */
    public func replacekey(key: String) {
        testKey = key
    }
    
    func runEncryptDecrypt(data: Data, kState: kEncryptDecrypt) -> Data? {
        encryptAbstractMethod()
        return nil
    }
}
extension SymmetricEncryptDecryptProducer {
    /**
     保证key的长度和算法长度对应位
     */
    func getBitKey(oldString: String, keyCount: Int) -> String {
        guard oldString.count != keyCount else{
            return oldString
        }
        var newString:String
        if oldString.count > keyCount {
            newString = String(oldString.prefix(keyCount))
        }else{
            newString = oldString.appendingFormat(String(format: "%%0%lud", keyCount - oldString.count) ,0)
        }
        return newString
    }
    /**
     保证key的长度和算法长度对应位（chacha20、AES_GCM的key为data数据转SymmetricKey，无法添加0为补充）
     */
    func getBitKey(keyString: String, keyCount: Int) -> Data? {
        if let keyData = keyString.data(using:.utf8) {
             var useData = keyData
            if keyData.count > keyCount {
                useData = keyData.subdata(in: 0 ..< keyCount)
            } else if keyData.count < keyCount {
                if let makeData = makeUpKey.data(using: .utf8) {
                    let bytes = [UInt8](makeData)
                    useData.append(bytes, count: keyCount - keyData.count)
                }
            }
            return useData
        }
        return nil
    }
    
    /**
     生成 CBC 模式使用的 IV。
     - Parameters:
        - blockSize: 算法分组长度，AES 为 16，DES/3DES/CAST/RC2/Blowfish 为 8
        - provided : 调用方指定的 IV；传 nil 表示由本方法生成随机 IV
     - Returns: 合法的 IV 数据；调用方传入的 IV 长度不匹配时返回 nil（不静默截断，避免"加了密却解不开"）
     */
    func makeIVData(blockSize: Int, provided: Data?) -> Data? {
        if let iv = provided {
            guard iv.count == blockSize else {
                let tips = "\(tips_iv_length)\(blockSize)"
                errorTips(tips: tips)
                assertionFailure(tips)
                return nil
            }
            return iv
        }
        var bytes = [UInt8](repeating: 0, count: blockSize)
        var generator = SystemRandomNumberGenerator()
        for index in 0..<blockSize {
            bytes[index] = UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
        }
        return Data(bytes)
    }
    
    /**
     对称加解密统一入口：收口 ECB / CBC 的差异。
     子类只需提供算法相关参数（alg / keyLength / blockSize），
     模式选择、IV 生成与前置、密文中 IV 的还原、缓冲区管理都在此处完成，
     避免同一段逻辑在各算法类中重复实现。
     - Parameters:
        - data      : 原始数据（加密为明文，解密为密文）
        - kState    : 加密 | 解密
        - key       : 文本密钥，长度由 getBitKey 自动补齐/截断
        - alg       : 算法标准
        - keyLength : key 长度
        - blockSize : 分组长度，用于计算缓冲区大小
     - Returns: 加解密后的数据；参数不合法（如流密码使用 CBC、密文长度不足、IV 长度错误）时返回 nil
     */
    final internal func EDWithMode(data: Data,
                                   kState: kEncryptDecrypt,
                                   key: String,
                                   alg: CCAlgorithm,
                                   keyLength: Int,
                                   blockSize: Int) -> Data? {
        let op = stateOp(kState: kState)
        switch cipherMode {
        case .ecb:
            // 兼容路径：options、key 补齐、缓冲区计算均与旧版本实现保持一致
            return _ccRun(payload: data, key: key, op: op, alg: alg,
                          options: CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode),
                          keyLength: keyLength, blockSize: blockSize, ivData: nil)
        case .cbc(let providedIV):
            // RC4 是流密码，没有分组概念，CBC 对其无意义
            guard alg != CCAlgorithm(kCCAlgorithmRC4) else {
                errorTips(tips: error_cbc_stream_not_supported)
                assertionFailure(error_cbc_stream_not_supported)
                return nil
            }
            let options = CCOptions(kCCOptionPKCS7Padding)
            if kState == .kEncrypt {
                guard let iv = makeIVData(blockSize: blockSize, provided: providedIV) else {
                    return nil
                }
                // IV 只作为偏移向量参与运算，不进入被加密的数据；
                // 加密完成后把 IV 前置到密文头部，使密文自包含（解密方无需另外保存/传递 IV）
                let cipher = _ccRun(payload: data, key: key, op: op, alg: alg,
                                    options: options, keyLength: keyLength,
                                    blockSize: blockSize, ivData: iv)
                return cipher.isEmpty ? nil : iv + cipher
            }
            // 解密：从密文头部还原 IV，其余部分作为密文数据
            guard data.count > blockSize else {
                errorTips(tips: error_cipher_length)
                assertionFailure(error_cipher_length)
                return nil
            }
            let iv = data.subdata(in: 0..<blockSize)
            let payload = data.subdata(in: blockSize..<data.count)
            return _ccRun(payload: payload, key: key, op: op, alg: alg,
                          options: options, keyLength: keyLength,
                          blockSize: blockSize, ivData: iv)
        }
    }
    
    /**
     执行一次 CCCrypt：统一处理 key 补齐与 IV 指针的生命周期（IV 指针仅在闭包内有效）。
     - Parameters:
        - payload   : 真正参与运算的数据（加密为明文，解密为密文）
        - ivData    : 偏移向量；ECB 传 nil，CBC 传长度等于分组长度的数据
     - Returns: 运算结果（与原 EncryptOrDecrypt 行为一致，失败时为空 Data）
     */
    final internal func _ccRun(payload: Data,
                               key: String,
                               op: UInt32,
                               alg: CCAlgorithm,
                               options: CCOptions,
                               keyLength: Int,
                               blockSize: Int,
                               ivData: Data?) -> Data {
        let useKey = getBitKey(oldString: key, keyCount: keyLength)
        return useKey.withCString { (keyPtr: UnsafePointer<CChar>) -> Data in
            guard let ivData = ivData else {
                return EncryptOrDecrypt(payload, keyPtr, op, alg, options, keyLength, blockSize, nil)
            }
            return ivData.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Data in
                EncryptOrDecrypt(payload, keyPtr, op, alg, options, keyLength, blockSize, buffer.baseAddress)
            }
        }
    }
    
    /**
     对称 加密解密的核心方法 （不包含chacha20、AES_GCM）
     - Parameters:
        -  data : 原始的数据
        -  key : key
        -  op: 加密｜解密
        -  alg: 类型
        -  options: 补码方式
        -  keyLength: key长度
        -  blockSize: 用来计算缓冲区及接受数据大小
        -  iv: 偏移向量；ECB 模式传 nil，CBC 模式传长度为分组长度的数据
     - returns   : 加解密后的数据
     */
    final internal func EncryptOrDecrypt(_ data: Data,
                                         _ key: UnsafeRawPointer,
                                         _ op: CCOperation,
                                         _ alg: CCAlgorithm,
                                         _ options: CCOptions,
                                         _ keyLength: Int,
                                         _ blockSize: Int,
                                         _ iv: UnsafeRawPointer? = nil)  -> Data {
        
        let stringBufferSize    = size_t(data.count)
        let bufferPtrSize       = (stringBufferSize + blockSize) & ~(blockSize - 1)

        let dataBytes           = (data as NSData).bytes
        guard let bufferPtr = malloc(bufferPtrSize * MemoryLayout<UInt8>.size) else {
            errorTips(tips: error_malloc_failed)
            assertionFailure(error_malloc_failed)
            return Data()
        }
        
        memset(bufferPtr, 0x0, bufferPtrSize)
        
        var movedBytes:size_t   = 0
        
        let res = CCCrypt(op,                // op: CCOperation 加密 | 解密
                          alg,               // alg: CCAlgorithm 加密算法标准
                          options,           // options:CCOptions 补码方式，CBC 模式不追加 kCCOptionECBMode
                          key,               // key:UnsafeRawPointer 加解密的密钥
                          keyLength,         // keyLength:Int 加解密key的长度
                          iv,                // iv:UnsafeRawPointer 偏移向量，CBC 模式需要；ECB 模式传 nil
                          dataBytes,         // dataIn:加解密数据的byte
                          stringBufferSize,  // dataInLength: 加解密数据的长度
                          bufferPtr,         // dataOut:加解密后的数据总数据的大小
                          bufferPtrSize,     // dataOutAvailable:加解缓冲区的大小
                          &movedBytes)       // dataOutMoved:加解密成功之后写入的地址
        // 失败时必须先释放缓冲区再返回，避免内存泄漏；
        // 且此时 movedBytes 未被 CCCrypt 保证写入，不能据此构造 Data
        guard res == kCCSuccess else {
            free(bufferPtr)
            let tips = "\(error_encrypt_decrypt)\(res)"
            errorTips(tips: tips)
            assertionFailure(tips)
            return Data()
        }
        // 截取加解密成功后的地址
        let resData = Data.init(bytes: bufferPtr, count: movedBytes)
        free(bufferPtr)
        return resData
    }
    /**
     设置加解密状态
     */
    func stateOp(kState: kEncryptDecrypt) -> UInt32 {
        if kState == .kEncrypt{
            return UInt32(CCOperation(kCCEncrypt))
        }
        return UInt32(CCOperation(kCCDecrypt))
    }
}
