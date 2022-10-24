//
//  ViewController.swift
//  LinnoEncrypt
//
//  Created by linnoIt on 09/30/2022.
//  Copyright (c) 2022 linnoIt. All rights reserved.
//

import UIKit
import LinnoEncrypt

class ViewController: UIViewController {
    
    // Symmetric class test
    
    
    var test3DES:_3DES = _3DES.init(key: "test")
    
    var testDES:DES = DES.init(key: "test")
    
    var testAES192:AES = AES(key: "test", keySize: .AES192)
    
    var testAES256:AES = AES(key: "test", keySize: .AES256)
    
    let text1 = "测试内容"
    
    var rsa = RSA()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        RSATest()
        hashTest()
        symmetricEDTest()
        // Do any additional setup after loading the view, typically from a nib.
    }

    // MARK: RSA 加密测试
    func RSATest() {
//        // 自己本地创建
//        rsa.generateRSAKeyPair()
//        // 从本地钥匙串中设置公钥和私钥
//        rsa.setRSAKey()
        // 从字符串中设置公钥
        rsa.setPublicSecKey(keyString: "MIGJAoGBANAKZDDzxuOxzNZVGVoZH+rgG2/57OXNXdxCYRD5s7ycWMlnScqaiSpVpElCUeCfqthddn0Auae1GtEkbTfxEpWIfHlsvMP7OvMUgImvoIofY1PetjYJCE/FQSHWrjW7YF14naFHCzN2lf0jAQVO8maKS6JEh3NrJyTovVk+wzQDAgMBAAE=")
        // 从字符串中设置私钥
        rsa.setPrivateSecKey(keyString: "MIICXAIBAAKBgQDQCmQw88bjsczWVRlaGR/q4Btv+ezlzV3cQmEQ+bO8nFjJZ0nKmokqVaRJQlHgn6rYXXZ9ALmntRrRJG038RKViHx5bLzD+zrzFICJr6CKH2NT3rY2CQhPxUEh1q41u2BdeJ2hRwszdpX9IwEFTvJmikuiRIdzayck6L1ZPsM0AwIDAQABAoGAEB+C2BsuFbugw32kSz8sofnZw1BfXTuQyiWBobZDotrx5wEwjvMLrVjzNG0SeZhpcUvkOnGoPpVpE76OEZDteFiAFtaVKP6OSMp7U3x95TezM908L/S26oILRKOhVkhpUPdb6uNa8rSZUJZyHp/d12xSOi3CMqNDRTs5zzhfAQECQQDwos5AH3IN6tFXofKXy5bwxhZbDVAO17ODczVaq5FE/a2DLc+SS1wrzbWMEEL86hD4PYADt17TFiRxf+iM85sDAkEA3VLQgP5gYbV5WCOT8SiofFGl8ldh89sOSjugPY118DlMPlCVEB9bH3SJTnnqjCdOpF0rkDFu7XaS0Kb3Q/ozAQJASHzioJJYazTXRwyz5WIg3/rr9RW3jiEQJILqCZwxMJUyVZfRNYKaC1/2VnD3nPRtlDoCfBwa5n9/Dum3Be7EPQJBANcXwONcVLcg8wkhqonZBcWsZCadneisn7qtMBIiBNiuFtcI4ZWFo71yOG84NSZ4nQlIMyozoKbPceeuHOjHpAECQDwUOAMdHYCG+5KYV1+DlCAYWx8qmA+H+aQbRsxnyH8HsQCkKTIzUfYmw2nvSTATQWfdFFVz10CPzCvQzH9NBd8=")
        
        
        let rsaEn = rsa.encrypt(text1)
        print("rsaEn = \(rsaEn)")
        print("*************************")
        let source = rsa.decrypt(rsaEn)
        print("source = \(source)")
        
        let publicSecKeyString = rsa.publicKeyString()
        print("publicSecKeyString = \(String(describing: publicSecKeyString))")
        
        let privateSecKeyString = rsa.privateKeyString()
        print("privateSecKeyString = \(String(describing: privateSecKeyString))")
        
    }
    
    
    // MARK: sha md5 散列测试
    func hashTest() {
//        008bd5ad93b754d500338c253d9c1770
//        008bd5ad93b754d500338c253d9c1770

       let md5String = MD5_USER.init().hashString(sourceString: "1994")
        
        print("md5String = \(md5String)")
        let string = "1994"
        _ = string.hashString.md5
        
        print("md5String = \(string.hashString.md5)")
        _ = string.hashString.sha256
        _ = string.hashString.sha384
        _ = string.hashString.sha512
        // ios 13+
//        5a478022f33905d2d40410e006fb1aa8564b280c
//        5a478022f33905d2d40410e006fb1aa8564b280c
        print("sha1 = \(string.hashString.sha1)")
    }
    
    // MARK: 对称加密测试
    func symmetricEDTest() {
        //008bd5ad93b754d500338c253d9c1770

        let kSource = "test"

        let other = otherEncry.init(key: "test", encryption: .Blowfish, keySize: .maxSize)
        let one1 = other.encrypt(kSource)

        print("other CAST === \(one1)")
        let one2 = other.decrypt(one1)

        print("other CAST === \(one2)")
    }
    
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

}

