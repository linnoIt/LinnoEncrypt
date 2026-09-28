//
//  AsymmetricTest.swift
//  LinnoEncrypt_Tests
//
//  Created by 韩增超 on 2022/11/2.
//  Copyright © 2022 CocoaPods. All rights reserved.
//
//  说明：本文件原先只有 print、没有任何断言（恒通过）。现改为确定性断言。
//

import XCTest
import LinnoEncrypt

final class AsymmetricTest: XCTestCase {

    /// 512 位 RSA 公钥（base64）。其模数为 64 字节，因此一个分组的密文正好是 64 字节。
    private let fixedPublicKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAPA5R50q+UJxfB5YZteo7Th6lXBq4ydZ9y7oBoJMhfaltt6KPH4JtIQ3gFLfX2jdSK7mrIa6yTFPA55e7eZzwmECAwEAAQ=="
    private let source = "LtGKzT3h3LuaSEOq"

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    /// 用固定公钥加密：密文长度必须等于一个密钥分组（512 bit = 64 字节），且只有公钥时无法解密
    func testEncryptWithFixedPublicKey() throws {
        var rsa = RSA()
        rsa.setPublicSecKey(keyString: fixedPublicKey)

        let cipher = rsa.encrypt(sourceString: source)
        XCTAssertFalse(cipher.isEmpty, "公钥加密不应返回空")
        XCTAssertEqual(Data(base64Encoded: cipher)?.count, 64,
                       "512 位 RSA 的密文应为 64 字节")

        XCTAssertTrue(RSA().encrypt(sourceString: source).isEmpty,
                      "未设置公钥时不应产出密文")
        XCTAssertTrue(rsa.decrypt(sourceString: cipher).isEmpty,
                      "仅持有公钥时不应能解密")
    }

    /// 公钥可从字符串装载并再次导出（验证 DER / base64 装载链路）
    func testPublicKeyStringRoundTrip() throws {
        var rsa = RSA()
        rsa.setPublicSecKey(keyString: fixedPublicKey)
        let exported = rsa.publicKeyString()
        XCTAssertNotNil(exported, "应能导出公钥字符串")
        XCTAssertFalse(exported?.isEmpty ?? true, "导出的公钥字符串不应为空")
    }

    /// RSA 加解密往返。密钥对在测试内直接生成（不经钥匙串），
    /// 这样用例只依赖加解密本身，不依赖测试宿主是否具备钥匙串写权限。
    func testRSAGenerateKeyPairAndRoundTrip() throws {
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                    kSecAttrKeySizeInBits as String: 1024]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let privateData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data?,
              let publicData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw XCTSkip("当前环境无法生成 RSA 密钥对")
        }

        var rsa = RSA(keySize: .size1024)
        rsa.setPublicSecKey(keyString: publicData.base64EncodedString())
        rsa.setPrivateSecKey(keyString: privateData.base64EncodedString())

        let cipher = rsa.encrypt(sourceString: source)
        XCTAssertFalse(cipher.isEmpty, "公钥加密不应返回空")
        XCTAssertEqual(Data(base64Encoded: cipher)?.count, 128,
                       "1024 位 RSA 的密文应为 128 字节")

        let decoded: String = rsa.decrypt(sourceString: cipher)
        XCTAssertEqual(decoded, source, "RSA 加解密往返失败")
    }

    /// 生成密钥对并导出 base64（不走钥匙串，避免依赖测试宿主的钥匙串写权限）
    private func makeKeyPairBase64(bits: Int) throws -> (pub: String, priv: String) {
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                    kSecAttrKeySizeInBits as String: bits]
        var error: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &error),
              let pub = SecKeyCopyPublicKey(priv),
              let privData = SecKeyCopyExternalRepresentation(priv, &error) as Data?,
              let pubData = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            throw XCTSkip("当前环境无法生成 RSA 密钥对")
        }
        return (pubData.base64EncodedString(), privData.base64EncodedString())
    }

    /// 大数据自动分块：1024 位下每块明文上限 = 128 - 11 = 117 字节，
    /// 密文长度必须是「分块数 × 128」，且解密后完整还原。
    func testRSALargeDataChunking() throws {
        let pair = try makeKeyPairBase64(bits: 1024)
        var rsa = RSA(keySize: .size1024)
        rsa.setPublicSecKey(keyString: pair.pub)
        rsa.setPrivateSecKey(keyString: pair.priv)

        for count in [1, 116, 117, 118, 234, 235] {
            let data = Data((0..<count).map { UInt8($0 % 251) })
            let cipher = rsa.encrypt(data)
            let blocks = (count + 116) / 117
            XCTAssertEqual(cipher.count, blocks * 128,
                           "输入 \(count) 字节应产出 \(blocks) 块 × 128 字节密文")
            XCTAssertEqual(rsa.decrypt(cipher), data, "分块往返失败（count=\(count)）")
        }
        XCTAssertTrue(rsa.encrypt(Data()).isEmpty, "空输入应返回空密文")
    }

    /// 密文被篡改 / 改用其他密钥，都必须解不出原文
    func testRSATamperAndWrongKeyRejected() throws {
        let pair = try makeKeyPairBase64(bits: 1024)
        let other = try makeKeyPairBase64(bits: 1024)

        var rsa = RSA(keySize: .size1024)
        rsa.setPublicSecKey(keyString: pair.pub)
        rsa.setPrivateSecKey(keyString: pair.priv)

        let msg = Data("LinnoEncrypt RSA tamper probe".utf8)
        var cipher = rsa.encrypt(msg)
        XCTAssertEqual(rsa.decrypt(cipher), msg, "正常往返失败")

        cipher[cipher.count - 1] ^= 0x01
        XCTAssertNotEqual(rsa.decrypt(cipher), msg, "篡改后的密文不应解出原文")

        var wrong = RSA(keySize: .size1024)
        wrong.setPrivateSecKey(keyString: other.priv)
        XCTAssertNotEqual(wrong.decrypt(cipher), msg, "错误私钥不应解出原文")
    }

    /// 空 / 非法密钥字符串必须「打印错误并返回空」，不得崩溃。
    /// 回归用例：此前 `takeRetainedValue()`（消费并释放 CFError）被写在取错误描述之前，
    /// 导致 SecKeyCreateWithData 失败时访问已释放对象 —— use-after-free（EXC_BREAKPOINT）。
    func testInvalidKeyStringDoesNotCrash() throws {
        var emptyPub = RSA()
        emptyPub.setPublicSecKey(keyString: "")
        XCTAssertTrue(emptyPub.encrypt(sourceString: source).isEmpty,
                      "空公钥字符串不应产出密文")

        var badPub = RSA()
        badPub.setPublicSecKey(keyString: "!!!not-a-valid-key!!!")
        XCTAssertTrue(badPub.encrypt(sourceString: source).isEmpty,
                      "非法公钥字符串不应产出密文")

        var emptyPriv = RSA()
        emptyPriv.setPrivateSecKey(keyString: "")
        XCTAssertTrue(emptyPriv.decrypt(sourceString: "AAAA").isEmpty,
                      "空私钥字符串不应产出明文")

        var badPriv = RSA()
        badPriv.setPrivateSecKey(keyString: "bm90LWEtdmFsaWQta2V5")
        XCTAssertTrue(badPriv.decrypt(sourceString: "AAAA").isEmpty,
                      "非法私钥字符串不应产出明文")
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
