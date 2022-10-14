//
//  Asymmetric.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/10/8.
//

import Foundation

public struct AsymmetricWrapper<Base> {
    public let base: Base
    public init(_ base: Base) {
        self.base = base
    }
}
public protocol AsymmetricCompatible: AnyObject { }

public protocol AsymmetricCompatibleValue {}

extension AsymmetricCompatible {
    
    public var Encrypt: AsymmetricWrapper<Self> {
        get { return AsymmetricWrapper(self) }
        set { }
    }
}





