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
        print("\(SymmetricClass.classForCoder) encode = \(resE)")
        if let resD:Array<Any> = SymmetricClass.decrypt(sourceString: resE){
            print("\(SymmetricClass.classForCoder) decode = \(resD)\n")
        }
    }
    func _symmetricEDTest<T>(SymmetricClass:T ,source:[String:Any]) where T : SymmetricEncryptionBase{
    
        let resE = SymmetricClass.encrypt(sourceDictionary: source)
        print("\(SymmetricClass.classForCoder) encode = \(resE)")
        if let resD:[String:Any] = SymmetricClass.decrypt(sourceString: resE){
            print("\(SymmetricClass.classForCoder) decode = \(resD)\n")
        }
    }
    
    
    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
