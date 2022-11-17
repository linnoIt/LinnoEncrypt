//
//  AsymmetricTest.swift
//  LinnoEncrypt_Tests
//
//  Created by 韩增超 on 2022/11/2.
//  Copyright © 2022 CocoaPods. All rights reserved.
//

import XCTest
import LinnoEncrypt

final class AsymmetricTest: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() throws {
        var rsa = RSA()

        let testString = "MIGJAoGBANAKZDDzxuOxzNZVGVoZH+rgG2/57OXNXdxCYRD5s7ycWMlnScqaiSpVpElCUeCfqthddn0Auae1GtEkbTfxEpWIf"
        
//        // 第一种 自己本地创建
//        rsa.generateRSAKeyPair()
//        // 第二种
//        // 从本地钥匙串中设置公钥和私钥
//        rsa.setRSAKey()
        // 第三种
        // 从字符串中设置公钥
        rsa.setPublicSecKey(keyString: "MIGJAoGBANAKZDDzxuOxzNZVGVoZH+rgG2/57OXNXdxCYRD5s7ycWMlnScqaiSpVpElCUeCfqthddn0Auae1GtEkbTfxEpWIfHlsvMP7OvMUgImvoIofY1PetjYJCE/FQSHWrjW7YF14naFHCzN2lf0jAQVO8maKS6JEh3NrJyTovVk+wzQDAgMBAAE=")
        // 从字符串中设置私钥
        rsa.setPrivateSecKey(keyString: "MIICXAIBAAKBgQDQCmQw88bjsczWVRlaGR/q4Btv+ezlzV3cQmEQ+bO8nFjJZ0nKmokqVaRJQlHgn6rYXXZ9ALmntRrRJG038RKViHx5bLzD+zrzFICJr6CKH2NT3rY2CQhPxUEh1q41u2BdeJ2hRwszdpX9IwEFTvJmikuiRIdzayck6L1ZPsM0AwIDAQABAoGAEB+C2BsuFbugw32kSz8sofnZw1BfXTuQyiWBobZDotrx5wEwjvMLrVjzNG0SeZhpcUvkOnGoPpVpE76OEZDteFiAFtaVKP6OSMp7U3x95TezM908L/S26oILRKOhVkhpUPdb6uNa8rSZUJZyHp/d12xSOi3CMqNDRTs5zzhfAQECQQDwos5AH3IN6tFXofKXy5bwxhZbDVAO17ODczVaq5FE/a2DLc+SS1wrzbWMEEL86hD4PYADt17TFiRxf+iM85sDAkEA3VLQgP5gYbV5WCOT8SiofFGl8ldh89sOSjugPY118DlMPlCVEB9bH3SJTnnqjCdOpF0rkDFu7XaS0Kb3Q/ozAQJASHzioJJYazTXRwyz5WIg3/rr9RW3jiEQJILqCZwxMJUyVZfRNYKaC1/2VnD3nPRtlDoCfBwa5n9/Dum3Be7EPQJBANcXwONcVLcg8wkhqonZBcWsZCadneisn7qtMBIiBNiuFtcI4ZWFo71yOG84NSZ4nQlIMyozoKbPceeuHOjHpAECQDwUOAMdHYCG+5KYV1+DlCAYWx8qmA+H+aQbRsxnyH8HsQCkKTIzUfYmw2nvSTATQWfdFFVz10CPzCvQzH9NBd8=")
        
        
        
        // 加密字符串
        let rsaEn = rsa.encrypt(sourceString: testString)
        print("rsaEn = \(rsaEn)")
        print("*************************")
        let rsaEd:String = rsa.decrypt(sourceString: rsaEn)
        print("source = \(rsaEd)")
        
        // 加密array
        let array = [1, 2, 3, 4, 5]
        if let rsaEnArray = rsa.encrypt(sourceArray: array) {
            print("*************************")
            if let rsaEdArray:Array<Any> = rsa.decrypt(sourceString: rsaEnArray){
                print("source = \(rsaEdArray)")
            }
           
        }

        // 加密Dictionary
        let dic = ["a":1,"b":"1"] as [String : Any]
        if let rsaEnDic = rsa.encrypt(sourceDictionary: dic) {
            print("*************************")
            if let rsaEdDic:[String : Any] = rsa.decrypt(sourceString: rsaEnDic){
                print("source = \(rsaEdDic)")
            }
        }
        // 获取公钥字符串
        let publicSecKeyString = rsa.publicKeyString()
        print("publicSecKeyString = \(String(describing: publicSecKeyString))")
        // 获取私钥字符串
        let privateSecKeyString = rsa.privateKeyString()
        print("privateSecKeyString = \(String(describing: privateSecKeyString))")
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
