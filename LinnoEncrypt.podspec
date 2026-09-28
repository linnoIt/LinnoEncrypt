#
# Be sure to run `pod lib lint LinnoEncrypt.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'LinnoEncrypt'
  s.version          = '0.2.0'
  s.summary          = 'linnoIt 自研 iOS 加解密组件：AES/DES/3DES/CAST/RC4/RC2/Blowfish、ChaCha20-Poly1305、AES-GCM、MD5/SHA/HMAC、RSA、Curve25519'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
LinnoEncrypt 是 linnoIt 自研的 iOS 加密组件库，覆盖对称加密、散列、消息认证与非对称加密，
支持 iOS 12 起步（CryptoKit 相关能力自 iOS 13 起可用），并提供 Objective-C 桥接。

- 对称加密：AES128/192/256、DES、3DES、CAST、RC4、RC2、Blowfish（CommonCrypto）；
  ChaCha20-Poly1305 与 AES-GCM（CryptoKit，含 wrapKey / unWrapKey）
- 散列：MD5（iOS 13 以下为库内自实现）、SHA1/256/384/512
- 消息认证：HMAC-MD5 / SHA1 / SHA256 / SHA384 / SHA512
- 非对称：RSA 512/1024/2048/4096，支持 keychain、DER 证书、P12 三种密钥装载方式
- 密钥协商与签名：Curve25519（KeyAgreement / Signing，hkdf 与 x963 派生）

工作模式默认 ECB，与 0.1.x 的密文逐字节兼容；0.2.0 起新增 CBC
（支持自动生成随机 IV 并前置到密文，也支持调用方指定 IV）。
                       DESC

  s.homepage         = 'https://github.com/linnoIt/LinnoEncrypt'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'linnoIt' => 'it@linno.cn' }
  s.source           = { :git => 'https://github.com/linnoIt/LinnoEncrypt.git', :tag => s.version.to_s }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.ios.deployment_target = '12.0'
  s.swift_version = '5.0'

  s.source_files = 'LinnoEncrypt/Classes/**/*'
  
  # s.resource_bundles = {
  #   'LinnoEncrypt' => ['LinnoEncrypt/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  # s.dependency 'AFNetworking', '~> 2.3'
end
