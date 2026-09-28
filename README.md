# LinnoEncrypt

[![Swift](https://img.shields.io/badge/Swift-5-orange?style=flat-square)](https://img.shields.io/badge/Swift-5-Orange?style=flat-square)
[![Version](https://img.shields.io/cocoapods/v/LinnoEncrypt.svg?style=flat)](https://cocoapods.org/pods/LinnoEncrypt)
[![License](https://img.shields.io/cocoapods/l/LinnoEncrypt.svg?style=flat)](https://cocoapods.org/pods/LinnoEncrypt)
[![Platform](https://img.shields.io/cocoapods/p/LinnoEncrypt.svg?style=flat)](https://cocoapods.org/pods/LinnoEncrypt)

## Example

To run the example project, clone the repo, and run `pod install` from the Example directory first.

## Requirements

Symmetric Encrypt & Asymmetric Decrypt

Symmetric support:

    AES DES 3DES CAST RC4 RC2 Blowfish ChaCha20 AES_GCM(ios13.0)

hash support:

    md5 sha1 sha256 sha384 sha512 HMAC

Asymmetric support:

    RSA

objective support:

    OCSupportShortcut_Hash
    OCSupportShortcut_RSA
    OCSupportShortcut_Symmetric
    
generate key:

    Curve_25519
    
Supported by update 16.4

## Cipher mode (since 0.2.0)

Symmetric algorithms support two working modes. The default is `.ecb`, which is byte-for-byte
compatible with 0.1.9 and earlier, so existing ciphertext can still be decrypted.

```swift
// Default: ECB (compatible with earlier versions)
let aes = AES(key: "your-key", keySize: .AES256)

// CBC with an auto-generated random IV, prepended to the ciphertext (recommended;
// the receiver does not need the IV separately)
let cbc = AES(key: "your-key", keySize: .AES256, cipherMode: .cbc(iv: nil))

// CBC with a caller-provided IV. Its length must equal the block size:
// AES 16, DES / 3DES / CAST / RC2 / Blowfish 8.
let fixed = AES(key: "your-key", keySize: .AES256, cipherMode: .cbc(iv: myIV))

// Switch at runtime
aes.replaceCipherMode(.cbc(iv: nil))
```

Objective-C:

```objc
OCSupportShortcut_Symmetric *aes = [[OCSupportShortcut_Symmetric alloc] initWithKey:@"key" mode:encryptModeAES256];
[aes useCBCMode];              // auto random IV
[aes useCBCModeWithIv:myIV];   // caller-provided IV
```

> RC4 is a stream cipher and has no block concept, so CBC is rejected for it:
> an error is printed and empty data is returned.

## Compatibility

- Default ECB ciphertext is byte-for-byte identical to 0.1.9; existing data decrypts unchanged.
- All new parameters have default values, so existing call sites compile without modification.
- Every previous public API is retained and usable.
- When no key is set, the library no longer falls back to the weak default `123456`;
  it prints an error and returns empty data instead.

## Migration notes (0.2.0)

- `H_MAC` / `Sha` / `MD5_USER`, and the `override init()` of `AES` / `DES` / `_3DES` / `otherEncry` / `AES_GCM`,
  are now `public`. Previously `AES()` / `DES()` / `_3DES()` / `otherEncry()` were **not constructible
  outside the module**, i.e. not from an app that integrates the pod — that is fixed.
- `Curve_25519.generateLocalPrivateKey(data:)` and `generateSigningPrinvateKey(data:)` had an inverted
  `guard`: calling them with the default `data: nil` crashed on a force-unwrap, while passing `data`
  silently ignored it. Fixed: no `data` → a new key; with `data` → the key is restored from `data`.
- `decrypt(sourceString:)` has four overloads that differ only by return type, so a bare
  `let x = obj.decrypt(...)` needs an explicit type annotation. Four unambiguous aliases were added for
  new code — `decryptToData` / `decryptToString` / `decryptToArray` / `decryptToDictionary` — while the
  original overloads stay exactly as they were.
- `H_MAC` no longer defaults to the weak key `"testKey"`, and an empty key no longer silently generates a
  random `SymmetricKey` (which made the MAC unreproducible). It prints an error and returns the input
  unchanged. `ChaCha20(key: nil)` likewise no longer generates a random key — an error is reported instead.
- Deprecated APIs replaced: `SecTrustEvaluate` → `SecTrustEvaluateWithError`, and
  `SecTrustCopyPublicKey` → `SecTrustCopyKey` on iOS 14+ (older systems keep the fallback).

## Changelog

See [CHANGELOG.md](CHANGELOG.md). CI runs `pod lib lint` plus the Example unit tests
(see `.github/workflows/ci.yml`).

## Installation

LinnoEncrypt is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod 'LinnoEncrypt'
```

## Author

linnoIt, it@linno.cn

## License

LinnoEncrypt is available under the MIT license. See the LICENSE file for more info.
