//
//  SymmetricType.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/9/30.
//

import Foundation

public enum kEncryptDecrypt {
    case kEncrypt
    case kDecrypt
}
protocol SymmetricType {
    func encryptDecryptSuccess(sourceString:String,kState:kEncryptDecrypt) -> String
}
