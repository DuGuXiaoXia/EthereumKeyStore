//
//  KeystoreKey.swift
//  welfarecoin
//
//  Created by alex on 2018/3/27.
//  Copyright © 2018年 http://kuaishangxian.com.cn/. All rights reserved.
//

import Foundation
import CryptoSwift
import SVProgressHUD

public struct KeystoreKey {
    
    /// Ethereum address.
    public var address: Address

    /// Account type.
    public var type: AccountType
    
    /// Wallet UUID, optional.
    public var id: String?
    
    /// Key header with encrypted private key and crypto parameters.
    public var crypto: KeystoreKeyHeader
    
    /// Mnemonic passphrase
    public var passphrase = ""
    
    /// Key version, must be 3.
    public var version = 3
    
    
    /// Initializes a `Key` by encrypting a mnemonic phrase with a password.
    public init(password: String, mnemonic: String, passphrase: String = "") throws {
        id = UUID().uuidString.lowercased()
        
        guard let cstring = mnemonic.cString(using: .ascii) else {
            throw EncryptError.invalidMnemonic
        }
        let data = Data(bytes: cstring.map({ UInt8($0) }))
        crypto = try KeystoreKeyHeader(password: password, data: data)
        
        type = .hierarchicalDeterministicWallet
        self.passphrase = passphrase
        
        let key = WalletCreate(mnemonic: mnemonic, passphrase: passphrase).getKey(at: 0)
        
        address = key.address
    } 

    /// Initializes a `Key` by encrypting a private key with a password.
    public init(password: String, key: Data) throws {
        id = UUID().uuidString.lowercased()
        crypto = try KeystoreKeyHeader(password: password, data: key)
        
        let pubKey = Secp256k1_ios.shared.pubicKey(from: key)
        address = KeystoreKey.decodeAddress(from: pubKey)
        type = .encryptedKey
    }
    /// Initializes a `Key` from a JSON wallet.
    public init(contentsOf url: URL) throws {
        let data = try Data(contentsOf: url)
        self = try JSONDecoder().decode(KeystoreKey.self, from: data)
        
    }
    
    
    /// Decrypts the key and returns the private key.
    public func decrypt(password: String) throws -> Data {
        
        let derivedKey: Data
        switch crypto.kdf {
        case "scrypt":
            let scrypt = Scrypt(params: crypto.kdfParams)
            derivedKey = try scrypt.calculate(password: password)
        default:
            throw DecryptError.unsupportedKDF
        }
        
        let mac = KeystoreKey.computeMAC(prefix: derivedKey[derivedKey.count - 16 ..< derivedKey.count], key: crypto.cipherText)
        if mac != crypto.mac {
            throw DecryptError.invalidPassword
        }
        
        let decryptionKey = derivedKey[0...15]
        let decryptedPK: [UInt8]
        switch crypto.cipher {
        case "aes-128-ctr":
            let aesCipher = try AES(key: decryptionKey.bytes, blockMode: .CTR(iv: crypto.cipherParams.iv.bytes), padding: .noPadding)
            decryptedPK = try aesCipher.decrypt(crypto.cipherText.bytes)
        case "aes-128-cbc":
            let aesCipher = try AES(key: decryptionKey.bytes, blockMode: .CBC(iv: crypto.cipherParams.iv.bytes), padding: .noPadding)
            decryptedPK = try aesCipher.decrypt(crypto.cipherText.bytes)
        default:
            throw DecryptError.unsupportedCipher
        }
        return Data(bytes: decryptedPK)
    }
   
    
    /// Decodes an Ethereum address from a public key.
    static func decodeAddress(from publicKey: Data) -> Address {
        precondition(publicKey.count == 65, "Expect 64-byte public key")
        precondition(publicKey[0] == 4, "Invalid public key")
        let sha3 = publicKey[1...].sha3(.keccak256)
        return Address(data: sha3[12..<32])
    }
    
    
    
    
    static func computeMAC(prefix: Data, key: Data) -> Data {
        var data = Data(capacity: prefix.count + key.count)
        data.append(prefix)
        data.append(key)
        return data.sha3(.keccak256)
    }
}


public enum DecryptError    : Error {
    case unsupportedKDF
    case unsupportedCipher
    case invalidCipher
    case invalidPassword
}

public enum EncryptError: Error {
    case invalidMnemonic
    case invalidPrivateKey
    case invalidKeystore
}

extension KeystoreKey: Codable {
    enum CodingKeys: String, CodingKey {
        case address
        case type
        case id
        case crypto
        case version
    }
    
    enum UppercaseCodingKeys: String, CodingKey {
        case crypto = "Crypto"
    }
    
    struct TypeString {
        static let privateKey = "private-key"
        static let mnemonic = "mnemonic"
    }
    
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let altValues = try decoder.container(keyedBy: UppercaseCodingKeys.self)
        
        address = Address(data: try values.decodeHexString(forKey: .address))
        switch try values.decodeIfPresent(String.self, forKey: .type) {
        case TypeString.mnemonic?:
            type = .hierarchicalDeterministicWallet
        default:
            type = .encryptedKey
        }
        id = try values.decode(String.self, forKey: .id)
        if let crypto = try? values.decode(KeystoreKeyHeader.self, forKey: .crypto) {
            self.crypto = crypto
        } else {
            // Workaround for myEtherWallet files
            self.crypto = try altValues.decode(KeystoreKeyHeader.self, forKey: .crypto)
        }
        version = try values.decode(Int.self, forKey: .version)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(address.description.drop0x(), forKey: .address)

        try container.encode(id, forKey: .id)
        try container.encode(crypto, forKey: .crypto)
        try container.encode(version, forKey: .version)
    }
}



private extension String {
    func drop0x() -> String {
        if hasPrefix("0x") {
            return String(dropFirst(2))
        }
        return self
    }
}
