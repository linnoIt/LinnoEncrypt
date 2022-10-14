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
    
    override func viewDidLoad() {
        super.viewDidLoad()
        let test:String = "test"
        // swift
        print("test md5 = \(test.Encrypt.md5)")
        // oc
        print("encryptSuccess = \(MD5().encryptSuccess(sourceString: test))")
        // let des = DES.init(key: "testkey")
        // let _3des = _3DES.init(key: "testkey")
        
        // otherEncry = CAST，RC4，RC2，Blowfish
        // let cast = otherEncry.init(key: "testkey") || otherEncry.init(key: "testkey", encryption: .CAST, keySize: .maxSize)
        
        // AES = AES128  AES192 AES256
        let aes = AES.init(key: "testkey",keySize: .AES256)
        let encryptString = aes.encryptDecryptSuccess(sourceString: "10010",kState: .kEncrypt)
        print("encryptString = \(encryptString)")
        let decryptString = aes.encryptDecryptSuccess(sourceString: encryptString, kState: .kDecrypt)
        print("decryptString = \(decryptString)")
        
        

        // Do any additional setup after loading the view, typically from a nib.
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

}

