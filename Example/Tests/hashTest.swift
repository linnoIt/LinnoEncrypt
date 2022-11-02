//
//  hashTest.swift
//  LinnoEncrypt_Tests
//
//  Created by 韩增超 on 2022/11/2.
//  Copyright © 2022 CocoaPods. All rights reserved.
//

import XCTest
import LinnoEncrypt


final class hashTest: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() throws {
        
        let hmacKey = "key"
        let testString = "this is test string"
        print(testString)
        
        // hash
        let md5 = testString.hashString.md5
        print(md5)
        
        let sha1 = testString.hashString.sha1
        print(sha1)
        
        let sha256 = testString.hashString.sha256
        print(sha256)
        
        let sha384 = testString.hashString.sha384
        print(sha384)
        
        let sha512 = testString.hashString.sha512
        print(sha512)
        
        
        // hmac hash
        let HMAC_md5 = testString.hashString.hmac(key: hmacKey, type: .MD5)
        print(HMAC_md5)
        
        let HMAC_sha1 = testString.hashString.hmac(key: hmacKey, type: .SHA1)
        print(HMAC_sha1)
        
        let HMAC_sha256 = testString.hashString.hmac(key: hmacKey, type: .SHA256)
        print(HMAC_sha256)
        
        let HMAC_sha384 = testString.hashString.hmac(key: hmacKey, type: .SHA384)
        print(HMAC_sha384)
        
        let HMAC_sha512 = testString.hashString.hmac(key: hmacKey, type: .SHA512)
        print(HMAC_sha512)
        
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        // Any test you write for XCTest can be annotated as throws and async.
        // Mark your test throws to produce an unexpected failure when your test encounters an uncaught error.
        // Mark your test async to allow awaiting for asynchronous code to complete. Check the results with assertions afterwards.
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
