//
//  Asymmetric.swift
//  QR
//
//  Created by 韩增超 on 2022/10/9.
//

import Foundation

// MARK: 测试 使用协议写法（参考Kingfisher的写法）
/** HashStruct结构，结构体内的类型为Base*/
public struct HashStruct<Base> {
    public let base: Base
    public init(_ base: Base) {
        self.base = base
    }
}
/** HashStructCompatible 空协议*/
public protocol HashStructCompatible: Any { }
/** HashStructCompatible 协议扩展*/
extension HashStructCompatible {
    /// Self = 当前调用 HashStruct 对象或者结构体的类型
    /// self = 当前调用 HashStruct 的对象或者结构体
    /** 添加hashString属性  */
    public var hashString: HashStruct<Self> {
        get { return HashStruct(self) }
        set { }
    }
}
/**
    给String 扩展HashStructCompatible 协议
    这样String就具有了hash属性
 */
extension String: HashStructCompatible { }
/**  当HashStruct结构体的Base为String的时候 扩展HashStruct*/
public extension HashStruct where Base == String {
    /**HashStruct 扩展属性md5    ⚠️⚠️⚠️不安全的 散列方式，不建议使用 */
    var md5: String {
        return  MD5_USER.init().hashString(sourceString: base)
    }
    /**HashStruct 扩展属性sha1    ⚠️⚠️⚠️不安全的 散列方式，不建议使用 */
    var sha1:String{
        Sha.init().hashString(sourceString: base, value: .hash1)
    }
    /**HashStruct 扩展属性sha256  */
    var sha256:String{
        Sha.init().hashString(sourceString: base, value: .hash256)
    }
    /**HashStruct 扩展属性hash384  */
    var sha384:String{
        Sha.init().hashString(sourceString: base, value: .hash384)
    }
    /**HashStruct 扩展属性hash512  */
    var sha512:String{
        Sha.init().hashString(sourceString: base, value: .hash512)
    }
    /**HashStruct 扩展属性HMAC方法  */
    func hmac(key:String,type:H_MAC.H_MAC_hashType) -> String{
        return H_MAC(key: key,type: type).hashString(sourceString: base)
    }
}

