//
//  Tests.swift
//  LinnoEncrypt_Tests
//
//  说明：本文件原先是模板占位（只有 XCTAssert(true, "Pass")，无实际校验）。
//  现改为对「公开入口」的冒烟测试。
//

import XCTest
import LinnoEncrypt

class Tests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    /// 散列公开入口：链式写法与 OC 桥接类结果一致
    func testHashPublicEntryPoints() throws {
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        XCTAssertEqual("hello".hashString.sha256, expected)
        XCTAssertEqual(OCSupportShortcut_Hash.hashString(source: "hello", type: .sha256),
                       expected,
                       "OC 桥接的散列结果应与 Swift 侧一致")
        XCTAssertEqual("hello".hashString.md5,
                       "5d41402abc4b2a76b9719d911017c592")
        XCTAssertEqual("hello".hashString.sha1,
                       "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
    }

    /// 对称加密公开入口：默认 ECB 的往返
    func testSymmetricSmoke() throws {
        let aes = AES(key: "0123456789abcdef", keySize: .AES128)
        let cipher = aes.encrypt(sourceString: "hello")
        XCTAssertFalse(cipher.isEmpty, "加密不应返回空")

        let decoded: String = aes.decrypt(sourceString: cipher)
        XCTAssertEqual(decoded, "hello", "默认 ECB 往返失败")
    }

    /// 0.2.0 新增的无歧义别名，结果须与既有同名重载完全一致
    func testDecryptAliasesMatchLegacyOverloads() throws {
        let aes = AES(key: "0123456789abcdef", keySize: .AES128)
        let cipher = aes.encrypt(sourceString: "hello")

        XCTAssertEqual(aes.decryptToString(sourceString: cipher), "hello")
        XCTAssertEqual(aes.decryptToData(sourceString: cipher), Data("hello".utf8))
        // 既有重载（需显式标注类型）同样可用
        let legacy: String = aes.decrypt(sourceString: cipher)
        XCTAssertEqual(legacy, "hello")

        let arrayCipher = aes.encrypt(sourceArray: [1, 2, 3]) ?? ""
        XCTAssertEqual(aes.decryptToArray(sourceString: arrayCipher)?.count, 3)

        let dictCipher = aes.encrypt(sourceDictionary: ["a": 1]) ?? ""
        XCTAssertEqual(aes.decryptToDictionary(sourceString: dictCipher)?.count, 1)
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure() {
            // Put the code you want to measure the time of here.
        }
    }

}
