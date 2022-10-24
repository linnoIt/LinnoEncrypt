//
//  SymmetricEncryptionBase.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import Foundation

public class SymmetricEncryptionBase: NSObject,EncryptDecryptType {
    
    public func encrypt(_ sourceString:String) -> String{
        encryptAbstractMethod()
    }
    public func decrypt(_ sourceString:String) -> String{
        encryptAbstractMethod()
    }
}
