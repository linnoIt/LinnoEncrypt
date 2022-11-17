//
//  TipsString.swift
//
//  Created by 韩增超 on 2022/10/18.
//

func errorTips(tips: String) {
    debugPrint(tips)
}
// error code  -------------------------------
//case incorrectKeySize
//密钥大小不正确。
//case invalidParameter
//参数无效。
//case incorrectParameterSize
//参数大小不正确。
//case underlyingCoreCryptoError(error: Int32)
//底层 corecrypto 库无法完成请求的操作。
//case authenticationFailure
//加密工具包错误.authentication失败
//case wrapFailure
//框架无法包装指定的密钥。
//case unwrapFailure
//框架无法解开指定的密钥。
// error code  -------------------------------

// public
var error_length: String { " the source count needs to be greater than 0 " }

var error_encrypt_decrypt: String { " encryptOrDecrypt Error code = " }

var error_base64_Decoding: String { " base64 Decoding Error " }

var error_abstract_method: String { " abstract method " }

// AsymmetricType
var error_save_keychain: String { " saveKeyToKeychain Failure " }

var error_get_keychain: String { " getKeyWithKeychain Failure " }

var error_certificates_path: String{ " The path is incorrect. The certificate file is not obtained " }

var error_der_notCoding: String{" The incoming data is not a valid der encoding " }

var error_string_get_secKey: String { " this string cannot be converted to a key " }

var error_create_privateKey: String { "privateKey Error For SecKeyCreateRandomKey: " }

// AsymmetricType && RSA
var error_public_secKey_null: String { " publicSecKey is Null " }

var error_private_secKey_null: String { " privateSecKey is Null " }

// RSA
var error_rsa_encrypt: String { " RSA encrypt/decrypt error, please check error information : " }

// chacha20
var error_chacha20_encrypt: String { " ChaCha20 encrypt/decrypt error " }

var tips_key_length: String{ " The length of the encrypted password is insufficient: " }

var tips_chacha20_no_supported: String { " chacha20 not supported Versions earlier than 13.0 " }

// ExtensionWithBase
var tips_not_converted_JSON: String { " This object cannot be converted to a JSON string " }

// H_MAC
var error_H_MAC_source_error: String { " error: sourceString not supported " }

var error_H_MAC_key_error: String { " error: key not supported " }

var error_H_MAC_system_error: String { " error: system error " }

// Curve_25519
var error_curve_25519_data_generate_key_error: String { " error: Failed to obtain the key from the data. Procedure " }

var error_curve_25519_shared_key_error: String { " error: Failed generate shared key " }

var error_curve_25519_signing_error: String { " error: Failed signing " }


// AES_GCM
var error_AES_GCM_encrypt_error: String { " error: Failed to AES_GCM encrypt " }
var error_AES_GCM_decrypt_error: String { " error: Failed to AES_GCM decrypt " }
var error_AES_GCM_wrapKey_error: String { " error: Failed to AES_GCM wrapKey " }
var error_AES_GCM_unWrapKey_error: String { " error: Failed to AES_GCM unWrapKey " }

// 
var error_converting_uint32: String{ " Error: converting data to UInt32 array " }

var tips_data_type_error: String { " The data format needs to be utf8" }
