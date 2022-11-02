//
//  MD5.swift
//  QR
//
//  Created by 韩增超 on 2022/9/27.
//

import Foundation
import CryptoKit


/*MD5以512位分组来处理输入的信息，且每一分组又被划分为16个32位子分组，算法的输出由四个32位分组组成，将这四个32位分组级联后将生成一个128位散列值。
 首先需要对信息进行填充，填充方法如下：先填充一个1，之后就是无数个0，直到使其字节长度对512求余数的结果等于448，（n*512) + 448 ,512-448 = 64位是用于表示填充前的信息长度。加上剩下的64位，即（n+1)*512,长度刚刚好是512的整数倍数。
 链接变量进行循环运算，得出结果。MD5中有四个32位被称作链接变量（Chaining Variable）的整数参数，他们分别为：A=0x01234567，B=0x89abcdef，C=0xfedcba98，D=0x76543210（此处为16进制原始数据）。当设置好这四个链接变量后，就开始进入算法的四轮循环运算
 */


/// iOS13之前，系统方法不提供MD5实现
/// 项目需要兼容oc，类继承的 hashString方法来完成转换

public final class MD5_USER:HashType{
    // 实现协议的 message
    var message: [UInt8] = []

    // 每轮的位移量
    private let shifts: [UInt32] = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                                    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    // 整数正弦
    private let sines: [UInt32] = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                                   0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                                   0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                                   0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                                   0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                                   0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                                   0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                                   0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                                   0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                                   0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                                   0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05,
                                   0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                                   0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                                   0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                                   0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                                   0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]
  
    // A=0x01234567
    // A的16进制表示
    // A: 01 23 45 67 （16进制）
    // A的二进制表示
    // A: 00000 0001 0010 0011 0100 0101 0110 0111 （二进制）
    // 计算机中首先编写的为低字节位，当从右向左获取字节数据(8位一个字节)时，最终A将变化为0x67452301
    // 散列值（链接变量）此处为计算机读取后的数据
    private let hashes: [UInt32] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    
    @objc public init(){
        
    }
    
    @objc public func hashString(sourceString: String) -> String {
        guard sourceString.count > 0 else {
            errorTips(tips: error_length)
           return error_length
        }
        let data = sourceString.data(using: .utf8)!
        /** iOS 13 后系统提供的MD5散列方法*/
        if #available(iOS 13.0, *) {
            
            let md5 = Insecure.MD5()
            
            return _hash(hashData: data, hashClass: md5)
            
        }
        /** iOS 13 前实现的散列方法*/
        else {
            message = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                    return [UInt8](bytes)
            }
            let MD5Data = calculate()
        
            var MD5String = String()
            
            for c in MD5Data {
                MD5String += String(format: "%02x", c)
            }
            return MD5String
        }
    }
    
    /** 循环计算 */
    func calculate() -> [UInt8] {
        // 获取到追加了长度的数据
        var tmpMessage = prepare(64)
        // reserveCapacity 比 append 性能更好，但是要明确内存的大小
        tmpMessage.reserveCapacity(tmpMessage.count + 4)
        // 散列值（链接变量）
        var hh = hashes
        // 获取 message bit length
        let lengthInBits = (message.count * 8)
        let lengthBytes = lengthInBits.bytes(64 / 8)
        // append message 原始长度的 bit
        tmpMessage += lengthBytes.reversed()
        
        // 设置每一块加密数据的的大小为512bit
        let chunkSizeBytes = 512 / 8 // 64
        // 将数据转换为序列块
        let chunkSequence = BytesSequenceIterator(chunkSize: chunkSizeBytes, data: tmpMessage)
        
        // 循环序列每一个块
        for chunk in chunkSequence {
            /// chunk = chunkSequence中data的数组切片
            ///与或运算 （并且将数组切片的数据类型转换为UInt32）
            let M:[UInt32] = toUInt32Array(chunk)
            assert(M.count == 16)
            guard M.count == 16 else {
                errorTips(tips: "Error converting data to UInt32 array")
                return []
            }
            // Initialize hash value for this chunk:
            var A: UInt32 = hh[0]
            var B: UInt32 = hh[1]
            var C: UInt32 = hh[2]
            var D: UInt32 = hh[3]

            var dTemp: UInt32 = 0

            // Main loop
            for j in 0 ..< sines.count {
                var g = 0
                var F: UInt32 = 0

                switch j {
                case 0...15:
                    F = (B & C) | ((~B) & D)
                    g = j
                    break
                case 16...31:
                    F = (D & B) | (~D & C)
                    g = (5 * j + 1) % 16
                    break
                case 32...47:
                    F = B ^ C ^ D
                    g = (3 * j + 5) % 16
                    break
                case 48...63:
                    F = C ^ (B | (~D))
                    g = (7 * j) % 16
                    break
                default:
                    break
                }
                dTemp = D
                D = C
                C = B
                B = B &+ rotateLeft((A &+ F &+ sines[j] &+ M[g]), bits: shifts[j])
                A = dTemp
            }

            hh[0] = hh[0] &+ A
            hh[1] = hh[1] &+ B
            hh[2] = hh[2] &+ C
            hh[3] = hh[3] &+ D
        }
        var result = [UInt8]()
        result.reserveCapacity(hh.count / 4)

        hh.forEach {
            // 小端地址 并且 与与计算
            let itemLE = $0.littleEndian
            let r1 = UInt8(itemLE & 0xff)
            let r2 = UInt8((itemLE >> 8) & 0xff)
            let r3 = UInt8((itemLE >> 16) & 0xff)
            let r4 = UInt8((itemLE >> 24) & 0xff)
            result += [r1, r2, r3, r4]
        }
        return result
    }
}

extension MD5_USER{
    /** 将UInt8的数组切片进行 与或运算 返回 UInt32 数组*/
    func toUInt32Array(_ slice: ArraySlice<UInt8>) -> [UInt32] {
        // 此处要返回的是UInt32类型的数组，所以获取到 UInt32 的Memory size
        let strideBy = MemoryLayout<UInt32>.size
        var result = [UInt32]()
        // 定义 result 的区间为 slice.count/strideBy
        result.reserveCapacity(slice.count/strideBy)
        // 每次取出strideBy个数据 将数据左移至同一片段
    
        for idx in stride(from: slice.startIndex, to: slice.endIndex, by: strideBy) {
            ///UInt32(slice[idx.advanced(by: 3)]) << n 的值为 UInt32(slice[idx.advanced(by: 3)]) *（2^n）。
            /// "<<" 是左移运算，换算成为二进制后，左移
            let d0 = UInt32(slice[idx.advanced(by: 3)]) << 24
            let d1 = UInt32(slice[idx.advanced(by: 2)]) << 16
            let d2 = UInt32(slice[idx.advanced(by: 1)]) << 8
            let d3 = UInt32(slice[idx])
            // 进行 与或（｜）运算 组合成 UInt32类型的数据
            let val: UInt32 = d0 | d1 | d2 | d3
            result.append(val)
        }
        return result
    }
    
    func rotateLeft(_ value: UInt32, bits: UInt32) -> UInt32 {
        return ((value << bits) & 0xFFFFFFFF) | (value >> (32 - bits))
    }
}








