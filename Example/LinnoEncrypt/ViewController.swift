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
        let test = _3DES.init(key: "testkey")
        let encryptString = test.encryptDecryptSuccess(sourceString: "10010",kState: .kEncrypt)
        print("encryptString = \(encryptString)")
        let decryptString = test.encryptDecryptSuccess(sourceString: encryptString, kState: .kDecrypt)
        print("decryptString = \(decryptString)")
//        let key = "testkey"
//        let desString =
        // Do any additional setup after loading the view, typically from a nib.
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

}

