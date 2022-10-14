//
//  MD5.swift
//  LinnoEncrypt
//
//  Created by 韩增超 on 2022/10/8.
//

import Foundation

/*MD5以512位分组来处理输入的信息，且每一分组又被划分为16个32位子分组，经过了一系列的处理后，算法的输出由四个32位分组组成，将这四个32位分组级联后将生成一个128位散列值。
 在MD5算法中，首先需要对信息进行填充，填充方法如下：先在信息后面填充一个1，之后就是无数个0，直到使其字节长度对512求余数的结果等于448，即（n*512) + 448 ,为什么要是余数为448呢，因为剩下的512-448 等于64位 是用于表示填充前的信息长度。加上剩下的64位，即（n+1)*512,长度刚刚好是512的整数倍数。
 然后就与链接变量进行循环运算，得出结果。MD5中有四个32位被称作链接变量（Chaining Variable）的整数参数，他们分别为：A=0x01234567，B=0x89abcdef，C=0xfedcba98，D=0x76543210。当设置好这四个链接变量后，就开始进入算法的四轮循环运算
 */
extension String: AsymmetricCompatibleValue { }
extension AsymmetricWrapper where Base == String {
    var md5: String {
        return base
//        guard let data = base.data(using: .utf8) else {
//            return base
//        }
//
//        let message = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
//            return [UInt8](bytes)
//        }
//
//        let MD5Calculator = MD5(message)
//        let MD5Data = MD5Calculator.calculate()
//
//        var MD5String = String()
//        for c in MD5Data {
//            MD5String += String(format: "%02x", c)
//        }
//        return MD5String
    }

    var ext: String? {
        var ext = ""
        if let index = base.lastIndex(of: ".") {
            let extRange = base.index(index, offsetBy: 1)..<base.endIndex
            ext = String(base[extRange])
        }
        guard let firstSeg = ext.split(separator: "@").first else {
            return nil
        }
        return firstSeg.count > 0 ? String(firstSeg) : nil
    }
}
