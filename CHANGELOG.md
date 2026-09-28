# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.2.0] - 2026-09-28

本次为**追加式**升级：不删除、不改名、不改签名任何既有公开 API，默认 ECB 路径的密文与 0.1.9 逐字节一致，
存量数据可继续解密。既有调用方一行不改即可编译。

### 新增

- 对称加密新增 `SymmetricCipherMode`（`.ecb` / `.cbc(iv:)`），由 `SymmetricEncryptDecryptProducer.replaceCipherMode(_:)` 或各算法构造参数 `cipherMode` 指定，默认 `.ecb`。
  - `.cbc(iv: nil)`：自动生成密码学安全的随机 IV，并把 IV 前置拼接在密文头部，解密自动取出，调用方无需管理 IV。
  - `.cbc(iv: data)`：使用调用方指定的 IV，长度须等于分组长度（AES 16；DES/3DES/CAST/RC2/Blowfish 8），长度不符直接报错而非静默截断。
  - RC4 为流密码，使用 `.cbc` 时显式报错。
- Objective-C 桥接新增 `OCSupportShortcut_Symmetric.useCBCMode()` 与 `useCBCMode(iv:)`。
- `EncryptDecryptType` 新增 4 个无歧义别名（既有同名重载全部保留）：
  `decryptToData(sourceString:)`、`decryptToString(sourceString:)`、`decryptToArray(sourceString:)`、`decryptToDictionary(sourceString:)`。
- `H_MAC`、`Sha`、`MD5_USER` 的 `init` 由 internal 放宽为 public，补齐模块外（其他项目经 CocoaPods 集成时）的可构造性。
- `AES` / `DES` / `_3DES` / `otherEncry` / `AES_GCM` 的 `override init()` 由 private 放宽为 public。
- `H_MAC` 能力扩展（全部为追加；既有 `hashString(sourceString:)` 的输出逐字符不变）：
  - 输出格式 `H_MAC_outputFormat`（`.hexLowercase` / `.hexUppercase` / `.base64`），经 `hashString(sourceString:format:)` / `hashString(data:format:)` 指定。
  - 原始字节出入口：`hashData(sourceString:)` / `hashData(data:)`，二进制数据不再需要编码转换。
  - 更换密钥：`replacekey(key:)`（与 `SymmetricEncryptDecryptProducer.replacekey` 同名同义）、`replacekey(data:)`（二进制 / 派生密钥）、`replacekey(symmetricKey:)`。
  - 恒定时间校验：`isValid(mac:for:)`、`isValid(macString:format:for:)`、`isValid(macString:for:)`（按位异或累加比较，无提前退出，可防时序侧信道）。
  - 一次性静态便捷方法：`H_MAC.hmac(data:key:type:format:)`。
  - 元信息：`H_MAC.digestLength` 与 `H_MAC_hashType.digestLength` 对外可见；`H_MAC_hashType` 补 `CaseIterable`。
  - Objective-C：`OCSupportShortcut_Hash` 新增 `hmacBase64(source:key:type:)` 与 `hmacVerify`（`macFormat` 枚举支持 hex 小写 / hex 大写 / Base64 三种格式，另有默认 hex 小写的便捷重载）。
- 新增 `CHANGELOG.md` 与 GitHub Actions 工作流（`pod lib lint` + Example 单测）。

### 修复

- **`AsymmetricType` 错误路径 use-after-free（P0，本轮回归）**：`getKeyWithData` 中
  `_ = error?.takeRetainedValue()`（按 Create Rule 消费并**释放** CFError）被写在了
  `String(describing: error)` **之前**，导致密钥装载失败时后续访问已释放对象 ——
  实测 `EXC_BREAKPOINT`（SIGTRAP）。0.1.9 的原始顺序本是正确的（先取描述、后消费），
  是本轮"去强解包"时调换行序引入的回归。
  已统一为「先取错误描述 → 再消费引用 → 断言用布尔快照」，`generateKeyPair` 同步整理为同一写法。
  触发条件：`SecKeyCreateWithData` 失败（如传入空或非法密钥字符串），合法密钥用例无法覆盖，
  由新增的跨版本 / 边界测试发现；已补回归用例 `testInvalidKeyStringDoesNotCrash`。
- **`RSA` 错误路径 CFError 泄漏**：`_secKeyToString` 与 `_encryptedDecryptedData` 声明了
  `Unmanaged<CFError>?` 却从不消费，失败时按 Create Rule 泄漏一个 CFError；现显式消费（顺序同上）。
- **内存泄漏**：`EncryptOrDecrypt` 中 `malloc` 后的错误分支未 `free`，每次失败泄漏一个缓冲区。
  实测同一错误路径调用 100 万次：修复前 RSS 增长 31.3 MB（32.80 字节/次，与 32 字节缓冲区吻合），修复后 256 KB。
  同时修正失败路径下用未初始化的 `movedBytes` 构造 `Data` 的越界读取。
- **弱默认密钥**：未显式设置密钥时不再回退到硬编码的 `"123456"`（对称）与 `"testKey"`（HMAC），
  改为打印错误并返回空数据。
- **静默随机密钥**：`ChaCha20(key: nil)` 与 HMAC 空 key 不再静默生成随机 `SymmetricKey`
  （那会让密文/MAC 永久无法复现），改为显式报错。
- **`fatalError` 抽象方法**：`SymmetricEncryptionBase` 的抽象方法兜底由 `Swift.Never`（必崩）改为
  "Debug 断言中断 / Release 打印错误并返回空"，与库内既有错误处理风格一致。
- **Curve25519 分支写反**：`generateLocalPrivateKey(data:)` 与 `generateSigningPrinvateKey(data:)`
  原实现中 `guard` 条件写反——不传 `data`（默认调用）时反而对 nil 强解包而崩溃，传了 `data` 又把它丢掉。
  已修正为：不传 `data` 生成新密钥，传了 `data` 用其还原密钥。
- **已弃用 API**：`SecTrustEvaluate`（iOS 13 起弃用）改用 `SecTrustEvaluateWithError`；
  取证书公钥在 iOS 14 起走 `SecTrustCopyKey`，更低版本回退 `SecTrustCopyPublicKey`。
  语义保持不变（该方法只负责从 DER 证书取公钥，不做信任链判定）。
- **强制解包收敛**：`RSA.generateRSAKeyPair` / `setPrivateSecKey` / `setPublicSecKey` /
  `_saveRSAKeyToKeychain`、`getKeyDataFrom`、`getPrivateKeyWithP12`、`String.hexadecimal()`、
  `_getContainerFromJSONString` 等以 `guard` 替代 `!`，非法输入不再直接崩溃。
- `_EDRun` 解密失败时不再误报 `error_length`。
- **`H_MAC` 缓冲区泄漏**：CommonCrypto 通道中 `result.deallocate()` 只在密钥转换成功分支调用，
  密钥转换失败时泄漏一个 `digestLength` 字节的缓冲区。
- **`H_MAC` 错误分支返回明文**：空密钥 / 源字符串编码失败时原实现返回 `sourceString`，
  Release 构建下调用方会**静默拿到明文当作 MAC**。现统一返回空值
  （该分支在 0.1.9 中不可达，不影响既有行为）。
- **`H_MAC` 依赖系统私有格式**：原实现从 CryptoKit 的 `description` 字符串里截取十六进制，
  格式一旦变化即静默返回空串；现直接读取 MAC 原始字节并自行格式化。
- **`H_MAC` 残留强解包**：iOS 13 以下通道的 `hashType as!` / `macKey as!` 已移除，`hashString` 补 `hashType` 校验。
- `H_MAC` 错误路径不再重复打印（密钥转换失败时同时报 key / source 两条日志）。
- **`HashType._hash` 依赖系统私有格式**（`Sha` / `MD5_USER` 的 iOS 13+ 路径，与 `H_MAC` 同源问题）：
  原实现 `hash.finalize().description` 后 `range(of: ": ")!` 截取十六进制 —— 既依赖 CryptoKit
  描述串的格式（形如 `SHA256 digest: <hex>`，系统一改即静默截取错误结果），又含一处强解包。
  改为 `withUnsafeBytes` 直接读取摘要字节并按 `%02x` 格式化。
  **输出逐字符不变**：已用 7 组输入 × 5 种算法（35 项）比对旧实现完全一致，
  并与 `openssl dgst` 独立计算的 5 种摘要逐字符相同；也与 iOS 13 以下 CommonCrypto 通道口径一致。
- **全库强制解包清零**：在上一轮已收敛的基础上，把剩余的可达强解包一并消除（均为行为等价改写）：
  - `AsymmetricType`：`error!.takeRetainedValue()` ×2（`error` 可能为 nil）、`spos!/epos!`、
    `key as! SecKey`（改用 `CFTypeID` 校验 + `Unmanaged` 取回，CF 类型不支持条件向下转换）。
  - `RSA`：`keyString!` / `P12Path!` / `DERPath!` / `publicSecKey!` ×2 / `privateSecKey!` ×2 / `datas.first!`。
    其中 `_encrypt` / `_decrypt` 保持原有的求值顺序，确保 `_encryptDecryptPrepare` 的错误日志照旧输出。
  - `OCSupportShortcut_RSA`：6 处 `rsa!` 改为可选链（键缺失时由崩溃变为返回空值，与库内失败姿态一致）。
  - `ChaCha20`：`keyDataString!` / `authenticating!`；`Curve25519`：`data!`。
  - `otherEncry`：`test[keyLengthFunString]!` 查表改为 `guard` + 断言（组合来自闭集枚举，0.1.9 不可达）。
  - `H_MAC`：CommonCrypto 通道的占位指针 `UnsafeRawPointer(bitPattern: 1)!` 移除，
    改为直接传 `baseAddress`（`CCHmac` 的 key/data 形参本身可空，长度为 0 时不解除引用；
    已用空 key / 空 data / 双空三组对照验证，结果与 RFC 向量一致）。
- **补齐显式 import（自包含化）**：17 个源文件补 `import Foundation`，`AsymmetricType` / `RSA` /
  `OCSupportShortcut` 另补 `import Security`，`H_MAC` 由 `CommonCrypto.CommonHMAC` 改为伞模块
  `CommonCrypto`（`CC_*_DIGEST_LENGTH` 来自 `CommonDigest`）。
  此前部分文件仅靠同模块内的传递可见性拿到 `Data` / `SecKey`，属于**编译顺序敏感**的脆弱依赖：
  单独对源码目录执行 `swiftc -typecheck` 时，报错文件会在 2～4 个之间漂移；
  补全后 21 个文件全部自包含，正序与倒序编译均 0 错误 0 警告。

### 验证

- ECB 密文基线：改动前后 24 项确定性密文逐字节一致（字典项因 JSON 键序不定单独排除）。
- `H_MAC` 已知向量：RFC 4231（SHA2 家族）与 RFC 2202（MD5 / SHA1）共 10 条 KAT，
  经 Python `hmac` 标准库与 `openssl dgst -mac HMAC -macopt hexkey` **双实现交叉验证**一致。
- `H_MAC` 双通道一致性：CommonCrypto `CCHmac` 与 CryptoKit `HMAC`，在二进制密钥、
  含 `0x00` 数据、空数据、空密钥四种输入下输出**字节级相同**。
- `H_MAC` 格式互通：hex 小写 / hex 大写 / Base64 / 原始字节四者互相自洽。
- CBC 正确性：与 `openssl` 独立计算的 AES-192-CBC / DES-CBC 已知向量完全一致。
- 旧公开 API：0.1.9 的全部调用形式（含 OC 桥接、四种返回类型重载、链式 hash、RSA / Curve25519 / GCM）
  在新版本下编译结果与 0.1.9 完全一致。
- 模块外可用性：`AES()` / `DES()` / `_3DES()` / `otherEncry()` 由 10 处报错降为 0。
- `HashType._hash` 改写等价性：旧实现（解析 CryptoKit `description`）与新实现（直接读摘要字节）
  在 7 组输入 × 5 种算法共 35 项上输出逐字符一致；并由 `openssl dgst` 独立计算 MD5 / SHA1 /
  SHA256 / SHA384 / SHA512 与 2 种 HMAC 交叉验证，与库输出完全相同。
- 密文与散列基线：以固定 key + 固定明文跑全部算法，与 0.1.9 基线逐行比对，
  24 项确定性结果（含 5 种散列与 2 种 HMAC）**逐字节一致**；
  仅 2 类用例因自身不确定性而变化并已单独排除——`ChaCha20`（随机 nonce）与字典入参
  （JSON 键序不定，实测同一二进制连跑 4 次其密文即自行改变），二者往返全部 OK。
- 全库静态检查：`Classes` 目录下已无 `!` 强解包、`as!`、`try!` 与隐式解包声明。
- iOS 12.0 部署目标下 `swiftc -typecheck`：0 错误 0 警告；正序与倒序（`ls -r`）两种编译顺序均通过，
  21 个源文件单文件检查无 `cannot find type 'Data'` 类报错，即各文件已自包含、不再依赖编译顺序。
- 单元测试：`xcodebuild test` **Debug 35 tests / 0 failures / 2 skipped**、
  **Release 35 tests / 0 failures / 0 skipped**，两配置均 `TEST SUCCEEDED`（负向用例在 Debug 按约定跳过、在 Release 真实执行）。
- 模块外可用性（新增 API）：以外部使用方身份、iOS 12 部署目标对已构建 framework 做 `-typecheck`，0 报错。
- **跨版本互通矩阵**（把 0.1.9 源码与当前源码各编译成一份 driver，经文件交换密钥与密文，验证真正的跨版本兼容）：
  - 对称加密：14 种算法 × 12 种输入（空串 / 二进制含 `0x00`·`0xff` / 中文 / 跨块长度 15·16·17·31·32·33 / 64 / 1000 字节），
    每组做「ECB 密文逐字节相同」「旧密文→新解密」「新密文→旧解密」三项检查，**492 项断言全部通过**。
    仅 ChaCha20 的密文比对按随机 nonce 排除（其往返仍校验）。
  - RSA：明文因 PKCS#1 v1.5 填充含随机字节而密文不定，故只能以互通方式验证 ——
    3 种密钥长度（512 / 1024 / 2048）× 6 种明文长度（每块上限 117·245 字节的 −1 / 正好 / +1 / 2 倍 / 2 倍 +1），
    **54 项断言全部通过**；密文长度恒为「分块数 × 块大小」。
- **RSA 与 openssl 交叉验证**：openssl 生成密钥对 → 库装载（PKCS#1 DER base64）；
  库加密 → openssl 解密；openssl 加密 → 库解密；多分块密文逐块经 openssl 解密后拼接与原文一致。
- **CBC 与 openssl 交叉验证**：AES-128/192/256-CBC、DES-CBC、3DES-CBC 在固定 key / IV 下
  与 `openssl enc -<alg>-cbc -K .. -iv .. -nosalt` 输出**逐字节一致**（DES / 3DES 需 openssl legacy provider）。
- **分块与填充规则不变**：14 种算法在 0/1/7/8/9/15/16/17/31/32/33/64/100/1000 字节共 14 个长度点上的
  密文长度表与 0.1.9 完全一致（含 RC4 不填充、DES 系 8 字节分组、AES 16 字节分组的补齐规则）。
- **CBC 工作模式全覆盖**：自动 IV（密文长度 = 分组长度 + 补齐后密文、两次 IV 不同、往返一致）；
  指定 IV（密文头部即传入的 IV、往返一致）；IV 长度不符被拒绝并返回空（不静默截断）。
- **AEAD 完整性**：AES-GCM 与 ChaCha20 在字符串 / 二进制 / 长数据（4–8 KB）下往返一致，
  密文被篡改 1 bit 后解密被拒绝。
- **RSA 分块边界**：1024 / 2048 位在每块上限的 −1 / 正好 / +1 / 2 倍 / 2 倍 +1 处的密文长度与还原完整性全部正确；
  篡改密文、使用错误私钥均解不出原文；空输入 / 缺公钥 / 缺私钥均返回空值。
- **AddressSanitizer**：以 `-sanitize=address` 编译并循环触发 RSA 与对称加密的错误路径，
  修复前顺序（`src-buggy` 对照副本）报 heap-use-after-free，当前代码无内存错误报告。
- `pod lib lint` 通过。

### 已知问题（未改，需另行评估）

- `EncryptDecryptType` 的 4 个 `decrypt(sourceString:)` 仅靠返回类型区分重载，直接 `let x = obj.decrypt(...)`
  需显式标注类型；本次以新增无歧义别名缓解，未改动既有重载（改动会破坏源码兼容）。
- `otherEncry` 中 RC4 沿用 `kCCBlockSizeRC2`（8）作为缓冲区对齐粒度。RC4 无分组概念，
  该值仅参与 `dataOutAvailable` 计算，改动会改变密文长度，故保持不变并加注释。
- `OCSupportShortcut_RSA(privateKeyPath:)` 走 P12 时未透传密码。
- `RSA.generateRSAKeyPair()` 写钥匙串的路径需在**真机**上复核：本机测试宿主与 macOS 命令行下
  `SecItemAdd` 均返回 `-25303`（errSecNoSuchAttr），且库内属性组合与最小属性组合返回**完全相同**的错误码，
  判定为该环境无钥匙串写权限、非库的属性组合缺陷，故未改动 Security 属性；
  单测中的 RSA 往返已改为不经钥匙串（测试内 `SecKeyCreateRandomKey` 后装入库），不依赖该环境能力。

## [0.1.9] - 2023-11-10

- 历史版本，最后一次发布。
