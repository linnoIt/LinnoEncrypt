//
//  Asymmetric.swift
//  QR
//
//  Created by 韩增超 on 2022/10/9.
//

import Foundation

// MARK: 测试 使用协议写法（参考Kingfisher的写法）
/** Asymmetric结构，结构体内的类型为Base*/
public struct Asymmetric<Base> {
    public let base: Base
    public init(_ base: Base) {
        self.base = base
    }
}
/** AsymmetricCompatible 空协议*/
public protocol AsymmetricCompatible: Any { }
/** AsymmetricCompatible 协议扩展*/
extension AsymmetricCompatible {
    /// Self = 当前调用 Encrypt 对象或者结构体的类型
    /// self = 当前调用 Encrypt 的对象或者结构体
    /** 添加Encrypt属性  */
    public var Encrypt: Asymmetric<Self> {
        get { return Asymmetric(self) }
        set { }
    }
}

/**
    给String 扩展AsymmetricCompatible 协议
    这样String就具有了Encrypt属性
 */
extension String: AsymmetricCompatible { }
/**  当Asymmetric结构体的Base为String的时候 扩展Asymmetric*/
extension Asymmetric where Base == String {
    /**Asymmetric 扩展属性md5  */
    public var md5: String {
        return MD5.init().encryptSuccess(sourceString: base)
    }
}

