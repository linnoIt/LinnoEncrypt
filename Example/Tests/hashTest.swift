//
//  hashTest.swift
//  LinnoEncrypt_Tests
//
//  Created by 韩增超 on 2022/11/2.
//  Copyright © 2022 CocoaPods. All rights reserved.
//
//  说明：本文件原先只有 print、没有任何断言（恒通过）。
//  现已改为与 OpenSSL / 系统 shasum 独立计算所得值对照的确定性断言。
//

import XCTest
import LinnoEncrypt
import CryptoKit

final class hashTest: XCTestCase {

    /// 已知向量所用明文
    private let testString = "this is test string"
    /// HMAC 所用密钥
    private let hmacKey = "key"

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    /// 链式散列：与 shasum / md5 的独立计算结果对照
    func testHashKnownVectors() throws {
        XCTAssertEqual(testString.hashString.md5,
                       "273bb6ccebe37f0a494eeb5d76540604",
                       "MD5 与独立计算结果不一致")
        XCTAssertEqual(testString.hashString.sha1,
                       "62d40fe74cf301cbfbe55c2679b96352449fb26d",
                       "SHA1 与独立计算结果不一致")
        XCTAssertEqual(testString.hashString.sha256,
                       "8e76c5b9e6be2559bedccbd0ff104ebe02358ba463a44a68e96caf55f9400de5",
                       "SHA256 与独立计算结果不一致")
        XCTAssertEqual(testString.hashString.sha384,
                       "8b1d372e11b9efbaedb0238e79af5f8c751e13653e4bf16fcfc496c9674873afeb4c43ecdce817bca237b59e9da53fa2",
                       "SHA384 与独立计算结果不一致")
        XCTAssertEqual(testString.hashString.sha512,
                       "3693b9b3002d6152cd2fa0ef03fb89ae13250dfc8ed0539b55c3cd8dc6938e414b11cb22baf5789e6f488b852d5d8188c821bfeb673876b5b7d1bc8831c77b24",
                       "SHA512 与独立计算结果不一致")
    }

    /// 链式 HMAC：与 `openssl dgst -hmac key` 的独立计算结果对照
    func testHMACKnownVectors() throws {
        XCTAssertEqual(testString.hashString.hmac(key: hmacKey, type: .MD5),
                       "f4f50cba4c34eed2b8be13a4f659247d",
                       "HMAC-MD5 与独立计算结果不一致")
        XCTAssertEqual(testString.hashString.hmac(key: hmacKey, type: .SHA1),
                       "5b178fd4d5af7e77a9eec4f4751a393cd778e815",
                       "HMAC-SHA1 与独立计算结果不一致")
        XCTAssertEqual(testString.hashString.hmac(key: hmacKey, type: .SHA256),
                       "f7cbd26fe403278dacf09c3a2a78ee247ee839679e48f2ed17ebb11c226fbb7d",
                       "HMAC-SHA256 与独立计算结果不一致")
        XCTAssertEqual(testString.hashString.hmac(key: hmacKey, type: .SHA384),
                       "cabc66992c4bb341c1fa96c10c1366e11e37375a9f926eba5fc14cdc4a3179319995825fe15496866a0eb175397863b4",
                       "HMAC-SHA384 与独立计算结果不一致")
        XCTAssertEqual(testString.hashString.hmac(key: hmacKey, type: .SHA512),
                       "692ef2facae6175b037b3509750be695dcd8f6e4891c7a925164df9e4d3b213d5226ccf38d09325742e6f37e2b731fbceb6cb89818dde0611b0120ca27c17bc3",
                       "HMAC-SHA512 与独立计算结果不一致")
    }

    /// H_MAC 直接构造（0.2.0 起 init 对外可用），结果须与链式写法完全一致
    func testHMACDirectInitMatchesChain() throws {
        let mac = H_MAC(key: hmacKey, type: .SHA256)
        XCTAssertEqual(mac.hashString(sourceString: testString),
                       testString.hashString.hmac(key: hmacKey, type: .SHA256),
                       "H_MAC 直接调用与链式写法结果不一致")
        XCTAssertEqual(mac.hashString(sourceString: testString),
                       "f7cbd26fe403278dacf09c3a2a78ee247ee839679e48f2ed17ebb11c226fbb7d")
    }

    /// 空 key 不再静默生成随机密钥（那会让结果每次不同、无法复现），也不再返回明文，
    /// 而是打印错误并返回空串。注意：Debug 构建下会按设计触发断言中断，因此该用例仅在 Release 配置下有效。
    func testEmptyHMACKeyDoesNotUseRandomKey() throws {
        #if DEBUG
        throw XCTSkip("Debug 构建下库会按约定触发断言，请在 Release 配置下运行该用例")
        #else
        let mac = H_MAC(key: "", type: .SHA256)
        XCTAssertEqual(mac.hashString(sourceString: testString), "",
                       "空 key 时应打印错误并返回空串（不得返回明文）")
        XCTAssertEqual(H_MAC().hashString(sourceString: testString), "",
                       "H_MAC 的弱默认 key 已移除，默认构造不应产出 MAC")
        XCTAssertEqual(mac.hashData(sourceString: testString), Data(),
                       "空 key 时原始字节输出同样为空")
        #endif
    }

    /// Sha 直接构造（0.2.0 起 init 对外可用）
    func testShaDirectInit() throws {
        XCTAssertEqual(Sha().hashString(sourceString: testString, hashType: .hash256),
                       "8e76c5b9e6be2559bedccbd0ff104ebe02358ba463a44a68e96caf55f9400de5")
    }

    // MARK: - 0.2.0 H_MAC 扩展
    // 以下已知向量均经 Python hmac 标准库与 openssl（-mac HMAC -macopt hexkey）双实现交叉验证，
    // 与 RFC 4231（SHA2 家族）、RFC 2202（MD5 / SHA1）一致。

    /** 构造指定算法 + 原始字节密钥的 MAC（hex 小写） */
    private func _macString(_ type: H_MAC.H_MAC_hashType, key: Data, data: Data) -> String {
        let mac = H_MAC(type: type)
        mac.replacekey(data: key)
        return mac.hashString(data: data, format: .hexLowercase)
    }

    /// RFC 4231 TC1：key = 0x0b × 20，data = "Hi There"
    func testHMACKAT_TC1() throws {
        let key = Data(repeating: 0x0b, count: 20)
        let data = Data("Hi There".utf8)
        XCTAssertEqual(_macString(.MD5, key: key, data: data),
                       "5ccec34ea9656392457fa1ac27f08fbc")
        XCTAssertEqual(_macString(.SHA1, key: key, data: data),
                       "b617318655057264e28bc0b6fb378c8ef146be00")
        XCTAssertEqual(_macString(.SHA256, key: key, data: data),
                       "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        XCTAssertEqual(_macString(.SHA384, key: key, data: data),
                       "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")
        XCTAssertEqual(_macString(.SHA512, key: key, data: data),
                       "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
    }

    /// RFC 4231 / RFC 2202 TC2：key = "Jefe"，data = "what do ya want for nothing?"
    func testHMACKAT_TC2() throws {
        let key = Data("Jefe".utf8)
        let data = Data("what do ya want for nothing?".utf8)
        XCTAssertEqual(_macString(.MD5, key: key, data: data),
                       "750c783e6ab0b503eaa86e310a5db738")
        XCTAssertEqual(_macString(.SHA1, key: key, data: data),
                       "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
        XCTAssertEqual(_macString(.SHA256, key: key, data: data),
                       "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        XCTAssertEqual(_macString(.SHA384, key: key, data: data),
                       "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")
        XCTAssertEqual(_macString(.SHA512, key: key, data: data),
                       "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")
    }

    /// 二进制 key / data（含 0x00、0xff）：覆盖 replacekey(data:) 与 Data 输入路径
    func testHMACBinaryKeyAndData() throws {
        let key = Data([0x00, 0x01, 0x02, 0xff, 0xfe])
        let data = Data([0x00, 0x61, 0x62, 0x63, 0xff])
        XCTAssertEqual(_macString(.MD5, key: key, data: data),
                       "5886434665192e95281309ef3c4ac435")
        XCTAssertEqual(_macString(.SHA1, key: key, data: data),
                       "a844bc1a2c222f16d0fbda2dd53b09f020a2c1e7")
        XCTAssertEqual(_macString(.SHA256, key: key, data: data),
                       "201f58e4f9ed2f4ff34182a9548261ea094905170041c2c11a7c066182f2a245")
    }

    /// 三种输出格式互通：base64 解码 == 原始字节，大写 hex == 小写 hex 的大写形式
    func testHMACOutputFormatInterop() throws {
        let key = Data([0x00, 0x01, 0x02, 0xff, 0xfe])
        let data = Data([0x00, 0x61, 0x62, 0x63, 0xff])
        let mac = H_MAC(type: .SHA256)
        mac.replacekey(data: key)

        let lower = mac.hashString(data: data, format: .hexLowercase)
        XCTAssertEqual(lower, "201f58e4f9ed2f4ff34182a9548261ea094905170041c2c11a7c066182f2a245")
        XCTAssertEqual(mac.hashString(data: data, format: .hexUppercase), lower.uppercased())
        XCTAssertEqual(mac.hashString(data: data, format: .base64),
                       "IB9Y5PntL0/zQYKpVIJh6glJBRcAQcLBGnwGYYLyokU=")

        let raw = mac.hashData(data: data)
        XCTAssertEqual(Data(base64Encoded: mac.hashString(data: data, format: .base64)), raw)
        XCTAssertEqual(mac.digestLength, 32)
    }

    /// replacekey：换 key 后与同 key 新实例一致、等于 TC2 已知向量；Data / SymmetricKey 密钥路径结果一致
    func testHMACReplaceKey() throws {
        let source = "what do ya want for nothing?"
        let mac = H_MAC(key: hmacKey, type: .SHA256)
        mac.replacekey(key: "Jefe")
        XCTAssertEqual(mac.hashString(sourceString: source),
                       "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        XCTAssertEqual(mac.hashString(sourceString: source),
                       H_MAC(key: "Jefe", type: .SHA256).hashString(sourceString: source))

        let binKey = H_MAC(type: .SHA256)
        binKey.replacekey(data: Data("Jefe".utf8))
        XCTAssertEqual(binKey.hashString(data: Data(source.utf8)),
                       mac.hashString(sourceString: source))

        if #available(iOS 13.0, *) {
            let sk = H_MAC(type: .SHA256)
            sk.replacekey(symmetricKey: SymmetricKey(data: Data("Jefe".utf8)))
            XCTAssertEqual(sk.hashString(data: Data(source.utf8)),
                           mac.hashString(sourceString: source))
        }
    }

    /// 恒定时间校验：正确通过、篡改 1 字节拒绝、长度不符拒绝、非法字符串拒绝、三种格式均可解析
    func testHMACIsValid() throws {
        let source = "what do ya want for nothing?"
        let mac = H_MAC(key: "Jefe", type: .SHA256)

        let hex = mac.hashString(sourceString: source, format: .hexLowercase)
        XCTAssertTrue(mac.isValid(macString: hex, for: source))
        XCTAssertTrue(mac.isValid(macString: hex.uppercased(),
                                  format: .hexUppercase, for: Data(source.utf8)))
        XCTAssertTrue(mac.isValid(macString: mac.hashString(sourceString: source, format: .base64),
                                  format: .base64, for: Data(source.utf8)))

        // 篡改 1 字节（首字节异或 0x01，'5' -> '4'，仍是合法 hex）
        var tamperedBytes = Array(hex.utf8)
        tamperedBytes[0] ^= 0x01
        let tampered = String(bytes: tamperedBytes, encoding: .utf8)!
        XCTAssertNotEqual(tampered, hex)
        XCTAssertFalse(mac.isValid(macString: tampered, for: source))

        // 长度不符
        XCTAssertFalse(mac.isValid(macString: String(hex.dropLast()), for: source))
        XCTAssertFalse(mac.isValid(macString: hex + "0", for: source))
        // 合法 hex 但值不对
        XCTAssertFalse(mac.isValid(macString: String(repeating: "ab", count: 16), for: source))
        // 无法解析的字符串
        XCTAssertFalse(mac.isValid(macString: "!!!", format: .base64, for: Data(source.utf8)))
    }

    /// digestLength：五种算法的摘要长度 + 实例属性 + CaseIterable
    func testHMACDigestLength() throws {
        XCTAssertEqual(H_MAC.H_MAC_hashType.MD5.digestLength, 16)
        XCTAssertEqual(H_MAC.H_MAC_hashType.SHA1.digestLength, 20)
        XCTAssertEqual(H_MAC.H_MAC_hashType.SHA256.digestLength, 32)
        XCTAssertEqual(H_MAC.H_MAC_hashType.SHA384.digestLength, 48)
        XCTAssertEqual(H_MAC.H_MAC_hashType.SHA512.digestLength, 64)
        XCTAssertEqual(H_MAC.H_MAC_hashType.allCases.count, 5)
        XCTAssertEqual(H_MAC().digestLength, 32, "默认算法为 SHA256")
        XCTAssertEqual(H_MAC(type: .SHA384).digestLength, 48)
    }

    /// 静态便捷方法：与实例路径、已知向量一致
    func testHMACStaticConvenience() throws {
        XCTAssertEqual(
            H_MAC.hmac(data: Data("what do ya want for nothing?".utf8),
                       key: Data("Jefe".utf8), type: .SHA256),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        XCTAssertEqual(
            H_MAC.hmac(data: Data([0x00, 0x61, 0x62, 0x63, 0xff]),
                       key: Data([0x00, 0x01, 0x02, 0xff, 0xfe]),
                       type: .SHA256, format: .base64),
            "IB9Y5PntL0/zQYKpVIJh6glJBRcAQcLBGnwGYYLyokU=")
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
