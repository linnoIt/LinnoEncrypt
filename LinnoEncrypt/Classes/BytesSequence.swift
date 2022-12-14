//
//  BytesSequence.swift
//  QR
//
//  Created by 韩增超 on 2022/10/14.
//
/**
 IteratorProtocol：一种一次提供一个序列值的类型
 Sequence:一种提供对元素的顺序、迭代访问的类型
 链表
 */
struct BytesSequenceIterator : Sequence, IteratorProtocol {
    // 分割序列块的长度
    let chunkSize: Int
    // 序列块保存的数据
    let data: [UInt8]
    // 从什么位置开始获取
    var offset = 0
    /// 1.ArraySlice 是数组或者其他 ArraySlice 的一段连续切片，和原数组共享内存。
    /// 2.当要改变 ArraySlice 的时候，ArraySlice 会 copy 出来，形成单独内存。
    /// 3.ArraySlice 拥有和 Array 基本完全类似的方法
    /** 实现迭代器的next方法，获取到数据data数组的下一块的数组切片*/
    mutating func next() -> ArraySlice<UInt8>? {
        let end = Swift.min(chunkSize, data.count - offset)
        let result = data[offset..<offset + end]
        offset += result.count
        return result.count > 0 ? result : nil
    }
}

