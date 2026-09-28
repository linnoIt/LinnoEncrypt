//
//  SymmetricTest.swift
//  LinnoEncrypt_Tests
//
//  Created by 韩增超 on 2022/11/2.
//  Copyright © 2022 CocoaPods. All rights reserved.
//

import XCTest
import LinnoEncrypt

final class SymmetricTest: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() throws {
        
        let text1 = "测试内容"
        let testArray = [1, 2, 3, 4, 5]
        let testDic = ["a":1 , "b":"1"] as [String : Any]
        
        let key = "你说啥呢，中文key会失败嘛，我不知道啊，可能是的吧"
        

        let test3DES:_3DES = _3DES.init(key:key)
        _symmetricEDTest(SymmetricClass: test3DES, source: text1)
        _symmetricEDTest(SymmetricClass: test3DES, source: testArray)
        _symmetricEDTest(SymmetricClass: test3DES, source: testDic)
        
        
        let testDES:DES = DES.init(key: key)
        _symmetricEDTest(SymmetricClass: testDES, source: text1)
        _symmetricEDTest(SymmetricClass: testDES, source: testArray)
        _symmetricEDTest(SymmetricClass: testDES, source: testDic)
        
        
        let testAES192:AES = AES(key: key, keySize: .AES192)
        _symmetricEDTest(SymmetricClass: testAES192, source: text1)
        _symmetricEDTest(SymmetricClass: testAES192, source: testArray)
        _symmetricEDTest(SymmetricClass: testAES192, source: testDic)

        
        let testAES256:AES = AES(key: key, keySize: .AES256)
        _symmetricEDTest(SymmetricClass: testAES256, source: text1)
        _symmetricEDTest(SymmetricClass: testAES256, source: testArray)
        _symmetricEDTest(SymmetricClass: testAES256, source: testDic)
        
        
        let other = otherEncry.init(key: key, encryption: .Blowfish, keySize: .maxSize)
        _symmetricEDTest(SymmetricClass: other, source: text1)
        _symmetricEDTest(SymmetricClass: other, source: testArray)
        _symmetricEDTest(SymmetricClass: other, source: testDic)
        
        
        let other1 = otherEncry.init(key: key, encryption: .RC4, keySize: .maxSize)
        _symmetricEDTest(SymmetricClass: other1, source: text1)
        _symmetricEDTest(SymmetricClass: other1, source: testArray)
        _symmetricEDTest(SymmetricClass: other1, source: testDic)
        
        
        let chaCha20 = ChaCha20.init(key: key)
        _symmetricEDTest(SymmetricClass: chaCha20, source: text1)
        _symmetricEDTest(SymmetricClass: chaCha20, source: testArray)
        _symmetricEDTest(SymmetricClass: chaCha20, source: testDic)
        
        
        
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        // Any test you write for XCTest can be annotated as throws and async.
        // Mark your test throws to produce an unexpected failure when your test encounters an uncaught error.
        // Mark your test async to allow awaiting for asynchronous code to complete. Check the results with assertions afterwards.
    }

    func _symmetricEDTest<T>(SymmetricClass:T ,source:String) where T : SymmetricEncryptionBase{
        print("*******************************")
        let resE = SymmetricClass.encrypt(sourceString: source)
        print("\(SymmetricClass.classForCoder) encode = \(resE)")
        let resD:String = SymmetricClass.decrypt(sourceString: resE)
        print("\(SymmetricClass.classForCoder) decode = \(resD)\n")
    }
    
    func _symmetricEDTest<T>(SymmetricClass:T ,source:Array<Any>) where T : SymmetricEncryptionBase{
      
        let resE = SymmetricClass.encrypt(sourceArray: source)
        print("\(SymmetricClass.classForCoder) encode = \(String(describing: resE))")
        if let resD:Array<Any> = SymmetricClass.decrypt(sourceString: resE ?? ""){
            print("\(SymmetricClass.classForCoder) decode = \(resD)\n")
        }
    }
    func _symmetricEDTest<T>(SymmetricClass:T ,source:[String:Any]) where T : SymmetricEncryptionBase{
    
        let resE = SymmetricClass.encrypt(sourceDictionary: source)
        print("\(SymmetricClass.classForCoder) encode = \(String(describing: resE))")
        if let resD:[String:Any] = SymmetricClass.decrypt(sourceString: resE ?? ""){
            print("\(SymmetricClass.classForCoder) decode = \(resD)\n")
        }
    }
    
    
    // MARK: - 0.2.0 新增：工作模式与错误路径的断言回归
    // 说明：以下用例给出确定性断言，用于在改动后立即发现"密文格式被破坏"。
    
    private func hexString(_ data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }
    
    private let assertKey = "0123456789abcdef0123456789abcdef"
    
    /// 默认 ECB 的密文必须与 0.1.9 逐字节一致，否则存量数据将无法解密
    func testDefaultECBKeepsLegacyCiphertext() throws {
        let aes = AES(key: assertKey, keySize: .AES192)
        XCTAssertEqual(aes.encrypt(sourceString: "LinnoEncrypt baseline: ECB mode @ 2026-09-28"),
                       "Ryw/ndPBwga6nESLvfn8Gn2t9CWGLKzQx/ML5p+Zg3aWfico87IP3I/4lnOH3Lx/",
                       "默认 ECB 密文发生变化，会破坏已上线版本的密文兼容性")
    }
    
    /// CBC + 自动 IV：IV 前置、密文自包含、每次加密结果不同
    func testCBCWithAutoIV() throws {
        let plain = "LinnoEncrypt-v0.2.0"
        let aes = AES(key: assertKey, keySize: .AES192, cipherMode: .cbc(iv: nil))
        let first = aes.encrypt(sourceString: plain)
        let second = aes.encrypt(sourceString: plain)
        let decoded: String = aes.decrypt(sourceString: first)
        
        XCTAssertEqual(decoded, plain, "CBC 往返失败")
        XCTAssertEqual(Data(base64Encoded: first)?.count, 48, "密文长度应为 IV(16) + 两个 AES 块(32)")
        XCTAssertNotEqual(first, second, "自动 IV 应当每次不同")
    }
    
    /// CBC + 指定 IV：结果确定，并与 OpenSSL 标准实现逐字节一致（交叉验证）
    func testCBCWithFixedIVMatchesOpenSSL() throws {
        let iv = Data((0..<16).map { UInt8($0) })
        let plain = "LinnoEncrypt-v0.2.0"
        let aes = AES(key: assertKey, keySize: .AES192, cipherMode: .cbc(iv: iv))
        let cipher = Data(base64Encoded: aes.encrypt(sourceString: plain))!
        let back: String = aes.decrypt(sourceString: cipher.base64EncodedString())
        
        XCTAssertEqual(cipher.subdata(in: 0..<16), iv, "密文头部应为传入的 IV")
        XCTAssertEqual(hexString(cipher.subdata(in: 16..<cipher.count)),
                       "00d8b636c2642232ded20703f5d3a570945e299cec5708f5d9301d9ea7b9bcd0",
                       "与 OpenSSL aes-192-cbc 的结果不一致")
        XCTAssertEqual(back, plain, "CBC 固定 IV 往返失败")
    }
    
    /// CBC 同样支持数组与字典
    func testCBCSupportsCollectionTypes() throws {
        let aes = AES(key: assertKey, keySize: .AES256, cipherMode: .cbc(iv: nil))
        let arrayCipher = aes.encrypt(sourceArray: [1, 2, 3, 4, 5]) ?? ""
        let arrayBack: [Any] = aes.decrypt(sourceString: arrayCipher) ?? []
        XCTAssertEqual(arrayBack.count, 5)
        
        let dictCipher = aes.encrypt(sourceDictionary: ["a": 1, "b": "1"]) ?? ""
        let dictBack: [String: Any] = aes.decrypt(sourceString: dictCipher) ?? [:]
        XCTAssertEqual(dictBack.count, 2)
    }
    
    /// 错误路径必须"打印错误并返回空"，而不是崩溃或静默用弱 key 加密。
    /// 注意：Debug 构建下会按设计触发断言中断，因此该用例仅在 Release 配置下有效。
    func testInvalidInputsFailSafely() throws {
        #if DEBUG
        throw XCTSkip("Debug 构建下库会按约定触发断言，请在 Release 配置下运行该用例")
        #else
        XCTAssertTrue(AES(key: "", keySize: .AES192).encrypt(sourceString: "x").isEmpty,
                      "未设置 key 时不应回退到弱默认值")
        let badIV = AES(key: assertKey, keySize: .AES192, cipherMode: .cbc(iv: Data(repeating: 1, count: 8)))
        XCTAssertTrue(badIV.encrypt(sourceString: "x").isEmpty, "IV 长度错误应被拒绝")
        let rc4CBC = otherEncry(key: assertKey, encryption: .RC4, keySize: .maxSize, cipherMode: .cbc(iv: nil))
        XCTAssertTrue(rc4CBC.encrypt(sourceString: "x").isEmpty, "流密码不支持 CBC")
        XCTAssertTrue(SymmetricEncryptDecryptProducer().encrypt(sourceString: "x").isEmpty,
                      "无参构造的 producer 不应使用弱 key 加密")
        #endif
    }
    
    /// 密文长度表必须稳定 —— 分块与 PKCS7 填充规则一旦被改动，存量密文即无法解密。
    /// 期望值取自与 0.1.9 的逐字节比对结果（两者密文长度表完全一致）。
    func testCipherLengthTableIsStable() throws {
        let aes = AES(key: assertKey, keySize: .AES192)
        for (n, expect) in [(1, 16), (7, 16), (15, 16), (16, 32), (17, 32), (31, 32), (32, 48), (33, 48), (64, 80), (100, 112), (1000, 1008)] {
            let cipher = aes.encrypt(Data(repeating: 0x41, count: n))
            XCTAssertEqual(cipher.count, expect,
                           "AES-192 ECB：输入 \(n) 字节的密文长度应为 \(expect)")
        }

        let des = DES(key: assertKey)
        for (n, expect) in [(1, 8), (7, 8), (8, 16), (9, 16), (16, 24), (17, 24)] {
            XCTAssertEqual(des.encrypt(Data(repeating: 0x41, count: n)).count, expect,
                           "DES ECB：输入 \(n) 字节的密文长度应为 \(expect)")
        }

        // 流密码（RC4）不做分块填充，密文长度恒等于明文长度
        let rc4 = otherEncry(key: assertKey, encryption: .RC4, keySize: .maxSize)
        for n in [1, 7, 8, 9, 15, 16, 17, 1000] {
            XCTAssertEqual(rc4.encrypt(Data(repeating: 0x41, count: n)).count, n,
                           "RC4 不填充：输入 \(n) 字节密文长度应为 \(n)")
        }
    }

    /// 二进制数据（含 0x00 / 0xff）与跨块长度必须可无损往返
    func testBinaryAndCrossBlockRoundTrip() throws {
        let samples: [Data] = [
            Data([0x00, 0x01, 0x02, 0xff, 0xfe, 0x00, 0x80, 0x7f]),
            Data(repeating: 0x00, count: 64),
            Data((0..<15).map { UInt8($0) }),
            Data((0..<16).map { UInt8($0) }),
            Data((0..<17).map { UInt8($0) }),
            Data((0..<255).map { UInt8($0) }),
        ]
        let engines: [SymmetricEncryptionBase] = [
            AES(key: assertKey, keySize: .AES128),
            AES(key: assertKey, keySize: .AES256),
            DES(key: assertKey),
            _3DES(key: assertKey),
            otherEncry(key: assertKey, encryption: .CAST, keySize: .maxSize),
            otherEncry(key: assertKey, encryption: .Blowfish, keySize: .maxSize),
            otherEncry(key: assertKey, encryption: .RC4, keySize: .maxSize),
            ChaCha20(key: assertKey),
        ]
        for engine in engines {
            for data in samples {
                let cipher = engine.encrypt(data)
                XCTAssertEqual(engine.decrypt(cipher), data,
                               "\(type(of: engine)) 二进制往返失败（len=\(data.count)）")
            }
        }
    }

    /// 二进制数据在 CBC 模式下同样可无损往返，且 IV 必须在密文头部
    func testCBCBinaryRoundTrip() throws {
        for (block, engine) in [(16, AES(key: assertKey, keySize: .AES192, cipherMode: .cbc(iv: nil)) as SymmetricEncryptionBase),
                                (8, DES(key: assertKey, cipherMode: .cbc(iv: nil)))] {
            let data = Data([0x00, 0xff, 0x00, 0x01, 0xfe]) + Data(repeating: 0xAB, count: 37)
            let cipher = engine.encrypt(data)
            XCTAssertEqual(engine.decrypt(cipher), data, "CBC 二进制往返失败")

            let iv = Data((0..<block).map { UInt8($0 + 1) })
            let fixed = AES(key: assertKey, keySize: .AES192, cipherMode: .cbc(iv: iv))
            if block == 16 {
                let c = fixed.encrypt(data)
                XCTAssertEqual(c.prefix(block), iv, "CBC 密文头部必须是传入的 IV")
                XCTAssertEqual(fixed.decrypt(c), data, "CBC 固定 IV 二进制往返失败")
            }
        }
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
