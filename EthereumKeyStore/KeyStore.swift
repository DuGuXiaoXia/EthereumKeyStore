//
//  KeyStore.swift
//  welfarecoin
//
//  Created by alex on 2018/3/27.
//  Copyright © 2018年 http://kuaishangxian.com.cn/. All rights reserved.
//

import Foundation
import KeychainSwift
import Result



public final class KeyStore {
    
    struct Keys {
        static let recentlyUsedAddress: String = "recentlyUsedAddress"
        static let recentlyUsedWallet: String = "recentlyUsedWallet"
        static let watchAddresses = "watchAddresses"
    }
    
    private let keychain: KeychainSwift = KeychainSwift(keyPrefix: __keychainKeyPrefix)
    
    public var recentlyKeychain: KeychainSwift {
        get {
            return keychain
        }
    }
    private let defaultKeychainAccess: KeychainSwiftAccessOptions = .accessibleWhenUnlockedThisDeviceOnly
    /// The key file directory.
    public let keyDirectory: URL
    let userDefaults: UserDefaults = UserDefaults.standard
    
    /// Dictionary of accounts by address.
    private var accountsByAddress = [Address: Account]()
    
    /// Dictionary of keys by address.
    private var keysByAddress = [Address: KeystoreKey]()
    
    /// Creates a `KeyStore` for the given directory.
    public init(keyDirectory: URL) throws {
        self.keyDirectory = keyDirectory
        
        
        
        try load()
    }
    
    private func load() throws {
        let fileManager = FileManager.default
        try? fileManager.createDirectory(at: keyDirectory, withIntermediateDirectories: true, attributes: nil)
        
        let accountURLs = try fileManager.contentsOfDirectory(at: keyDirectory, includingPropertiesForKeys: [], options: [.skipsHiddenFiles])
        for url in accountURLs {
            do {
                var key = try KeystoreKey(contentsOf: url)
                if url.absoluteString.contains("HD-UTC--") {
                    key.type = AccountType.hierarchicalDeterministicWallet
                }
                keysByAddress[key.address] = key
            
                let account = Account(address: key.address, type: key.type,  url: url)
                accountsByAddress[key.address] = account
            } catch {
                // Ignore invalid keys
            }
        }
    }
    
    
    /// List of accounts.
    public var accounts: [Account] {
        return Array(accountsByAddress.values)
    }
    
    /// Retrieves an account for the given address, if it exists.
    public func account(for address: Address) -> Account? {
        return accountsByAddress[address]
    }
    
    /// Retrieves a key for the given address, if it exists.
    public func key(for address: Address) -> KeystoreKey? {
        return keysByAddress[address]
    }
    
    
    private var watchAddresses: [String] {
        set {
            let data = NSKeyedArchiver.archivedData(withRootObject: newValue)
            return userDefaults.set(data, forKey: Keys.watchAddresses)
        }
        get {
            guard let data = userDefaults.data(forKey: Keys.watchAddresses) else { return [] }
            return NSKeyedUnarchiver.unarchiveObject(with: data) as? [String] ?? []
        }
    }
    
    var recentlyUsedWallet: Wallet? {
        set {
            keychain.set(newValue?.description ?? "", forKey: Keys.recentlyUsedWallet, withAccess: defaultKeychainAccess)
        }
        get {
            let walletKey = keychain.get(Keys.recentlyUsedWallet)
            let foundWallet = wallets.filter { $0.description == walletKey }.first
            guard let wallet = foundWallet else {
                // Old way to match recently selected address
                let address = keychain.get(Keys.recentlyUsedAddress)
                return wallets.filter {
                    $0.address.description == address || $0.address.description.lowercased() == address?.lowercased()
                    }.first
            }
            return wallet
        }
    }
    
    //MARK: - Creates a new account.
    public func createAccount(password: String, mnemonic: String) throws -> Account {
        var key = try KeystoreKey(password: password, mnemonic: mnemonic, passphrase:password)
        key.type = AccountType.hierarchicalDeterministicWallet
        keysByAddress[key.address] = key
        let url = makeAccountURL(for: key)
        let account = Account(address: key.address, type: .hierarchicalDeterministicWallet, url: url)
        setPassword(password, for: account)
        try save(account: account, in: keyDirectory)
        accountsByAddress[key.address] = account
        
        
        return account
    }

    //MARK: - import account
    func importWallet(type: ImportType, completion: @escaping (Result<Wallet, KeystoreError>) -> Void) {
        switch type {
        case .keystore(let string, let password):
            importKeystore(
                value: string,
                password: password,
                newPassword: password
            ) { result in
                switch result {
                case .success(let account):
                    
                    self.setPassword(password, for: account)
                    completion(.success(Wallet(type: .privateKey(account), walletName: "", walletHeadImageName: "")))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        case .privateKey(let privateKey, let password):
            keystore(for: privateKey, password: password) { result in
                switch result {
                case .success(let value):
                    self.importKeystore(
                        value: value,
                        password: password,
                        newPassword: password
                    ) { result in
                        switch result {
                        case .success(let account):
                            self.setPassword(password, for: account)
                            completion(.success(Wallet(type: .privateKey(account), walletName: "", walletHeadImageName: "")))
                        case .failure(let error):
                            completion(.failure(error))
                        }
                    }
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        case .mnemonic(let words, let passphrase):
            let string = words.map { String($0) }.joined(separator: " ")
            if !Mnemonic.isValid(string) {
                return completion(.failure(KeystoreError.invalidMnemonicPhrase))
            }
            do {
                let account = try self.import(mnemonic: string, passphrase: passphrase, encryptPassword: passphrase)
                setPassword(passphrase, for: account)
                completion(.success(Wallet(type: .hd(account), walletName: "", walletHeadImageName: "")))
            } catch {
                return completion(.failure(KeystoreError.duplicateAccount))
            }
        case .watch(let address):
            let addressString = address.description
            guard !watchAddresses.contains(addressString) else {
                return completion(.failure(.duplicateAccount))
            }
            self.watchAddresses = [watchAddresses, [addressString]].flatMap { $0 }
            completion(.success(Wallet(type: .address(address), walletName: "", walletHeadImageName: "")))
        }
    }
    
    func keystore(for privateKey: String, password: String, completion: @escaping (Result<String, KeystoreError>) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let keystore = self.convertPrivateKeyToKeystoreFile(
                privateKey: privateKey,
                passphrase: password
            )
            DispatchQueue.main.async {
                switch keystore {
                case .success(let result):
                    completion(.success(result.jsonString ?? ""))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        }
    }
    
    func importKeystore(value: String, password: String, newPassword: String, completion: @escaping (Result<Account, KeystoreError>) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            guard let data = value.data(using: .utf8) else {
                DispatchQueue.main.async {
                    completion(.failure(.failedToParseJSON))
                }
                return
            }
            do {
                let account = try self.import(json: data, password: password, newPassword: newPassword)
                let _ = self.setPassword(newPassword, for: account)
                DispatchQueue.main.async {
                    completion(.success(account))
                }
            } catch {
                DispatchQueue.main.async {
                    if case KeyStore.Error.accountAlreadyExists = error {
                        completion(.failure(.duplicateAccount))
                    } else {
                        completion(.failure(.failedToImport(error)))
                    }
                }
            }
        }
    }
    
    
    
    /// Imports an encrypted JSON key.
    ///
    /// - Parameters:
    ///   - key: key to import
    ///   - password: key password
    ///   - newPassword: password to use for the imported key
    /// - Returns: new account
    public func `import`(json: Data, password: String, newPassword: String) throws -> Account {
        let key = try JSONDecoder().decode(KeystoreKey.self, from: json)
        if self.account(for: key.address) != nil {
            throw Error.accountAlreadyExists
        }

        var privateKey = try key.decrypt(password: password)
        print(privateKey)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }

        let newKey = try KeystoreKey(password: newPassword, key: privateKey)
        keysByAddress[newKey.address] = newKey
        print(newKey.address)
        let url = makeAccountURL(for: key)
        let account = Account(address: newKey.address, type: key.type, url: url)
        try save(account: account, in: keyDirectory)
        accountsByAddress[newKey.address] = account

        return account
    }
    
    /// Imports a wallet.
    ///
    /// - Parameters:
    ///   - mnemonic: wallet's mnemonic phrase
    ///   - passphrase: wallet's password
    ///   - encryptPassword: password to use for encrypting
    /// - Returns: new account
    public func `import`(mnemonic: String, passphrase: String = "", encryptPassword: String) throws -> Account {
        let wallet = WalletCreate(mnemonic: mnemonic, passphrase: passphrase)
        let address = wallet.getKey(at: 0).address
        if self.account(for: address) != nil {
            throw Error.accountAlreadyExists
        }

        var newKey = try KeystoreKey(password: encryptPassword, mnemonic: mnemonic, passphrase: passphrase)
        newKey.type = AccountType.hierarchicalDeterministicWallet
        keysByAddress[newKey.address] = newKey

        let url = makeAccountURL(for: newKey)
        let account = Account(address: address, type: .hierarchicalDeterministicWallet, url: url)
        try save(account: account, in: keyDirectory)
        accountsByAddress[address] = account

        return account
    }
    
    
    
    var wallets: [Wallet] {
        let addresses = watchAddresses.flatMap { Address(string: $0) }
        return [
            self.accounts.map {
                switch $0.type {
                case .encryptedKey: return Wallet(type: .privateKey($0), walletName: self.getWalletName(for: $0)!, walletHeadImageName: self.getHeadImageName(for: $0)!)
                case .hierarchicalDeterministicWallet: return Wallet(type: .hd($0), walletName: self.getWalletName(for: $0)!, walletHeadImageName: self.getHeadImageName(for: $0)!)
                }
            },
            addresses.map { Wallet(type: .address($0), walletName: self.getWalletName(for: self.account(for: $0)!)!, walletHeadImageName: self.getHeadImageName(for: self.account(for: $0)!)!) },
            ].flatMap { $0 }
    }
    
    //MARK: - Exports an account as JSON data.
    ///
    /// - Parameters:
    ///   - account: account to export
    ///   - password: account password
    ///   - newPassword: password to use for exported key
    /// - Returns: encrypted JSON key
    public func export(account: Account, password: String, newPassword: String) throws -> Data {
        guard let key = keysByAddress[account.address] else {
            fatalError("Missing account key")
        }
        
        let keystore = self.recentlyKeychain.get(account.address.description.lowercased() + "keystore")
        
        guard keystore == nil || keystore == "" else{
            return (keystore?.data(using: .utf8))!
        }
        
        var privateKey = try key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }
        var newKey: KeystoreKey
        switch key.type {
        case .encryptedKey:
            newKey = try KeystoreKey(password: newPassword, key: privateKey)
        case .hierarchicalDeterministicWallet:
            guard let string = String(data: privateKey, encoding: .ascii) else {
                throw EncryptError.invalidMnemonic
            }
            newKey = try KeystoreKey(password: newPassword, key: WalletCreate(mnemonic: string, passphrase: key.passphrase).getKey(at: 0).privateKey)
        }
        return try JSONEncoder().encode(newKey)
    }
    
    
    
    //MARK: - Exports an account as private key data.
    ///
    /// - Parameters:
    ///   - account: account to export
    ///   - password: account password
    /// - Returns: private key data
    public func exportPrivateKey(account: Account, password: String) throws -> Data {
        guard let key = keysByAddress[account.address] else {
            fatalError("Missing account key")
        }

        var privateKey = try key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }

        switch key.type {
        case .encryptedKey:
            return privateKey
        case .hierarchicalDeterministicWallet:
            guard let string = String(data: privateKey, encoding: .ascii) else {
                throw EncryptError.invalidMnemonic
            }
            return WalletCreate(mnemonic: string, passphrase: key.passphrase).getKey(at: 0).privateKey
        }
    }
    
    //MARK: - Exports an account as Mnemonic .
    ///
    /// - Parameters:
    ///   - account: account to export
    ///   - password: account password
    /// - Returns: Mnemonic String
    
    public func exportMnemonic(account: Account, password: String) throws -> String {
        guard let key = keysByAddress[account.address] else {
            fatalError("Missing account key")
        }
        
        var privateKey = try key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }
        
        guard let mnemonic = String(data: privateKey, encoding: .ascii) else {
            throw EncryptError.invalidMnemonic
        }
        return mnemonic
    }
    
    /// Updates the password of an existing account.
    ///
    /// - Parameters:
    ///   - account: account to update
    ///   - password: current password
    ///   - newPassword: new password
    public func update(account: Account, password: String, newPassword: String)-> Bool {
        guard let key = keysByAddress[account.address] else {
            fatalError("Missing account key")
        }

        var privateKey = try! key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }
        guard privateKey.count <= 0 else {
            
            return false
        }
        var newKey: KeystoreKey
        switch key.type {
        case .encryptedKey:
            newKey = try! KeystoreKey(password: newPassword, key: privateKey)
        case .hierarchicalDeterministicWallet:
            guard let string = String(data: privateKey, encoding: .ascii) else {
                print(EncryptError.invalidMnemonic)
                return false
            }
            newKey = try! KeystoreKey(password: newPassword, mnemonic: string, passphrase: key.passphrase)
        }
        newKey.type = key.type
        keysByAddress[newKey.address] = newKey
        
        return true
    }
    
    /// Deletes an account including its key if the password is correct.
    public func delete(account: Account, password: String) throws {
        guard let key = keysByAddress[account.address] else {
            fatalError("Missing account key")
        }

        var privateKey = try key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }

        keysByAddress[account.address] = nil

        try FileManager.default.removeItem(at: account.url)
        accountsByAddress[account.address] = nil
    }
    
    /// Calculates a ECDSA signature for the give hash.
    ///
    /// - Parameters:
    ///   - data: hash to sign
    ///   - account: account to use for signing
    ///   - password: account password
    /// - Returns: signature
    /// - Throws: `DecryptError`, `Secp256k1Error`, or `KeyStore.Error`
//    public func signHash(_ data: Data, account: Account, password: String) throws -> Data {
//        guard let key = keysByAddress[account.address] else {
//            throw KeyStore.Error.accountNotFound
//        }
//        return try key.sign(hash: data, password: password)
//    }
    
    /// Signs an array of hashes with the given password.
    ///
    /// - Parameters:
    ///   - hashes: array of hashes to sign
    ///   - account: account to use for signing
    ///   - password: key password
    /// - Returns: array of signatures
    /// - Throws: `DecryptError` or `Secp256k1Error` or `KeyStore.Error`
//    public func signHashes(_ data: [Data], account: Account, password: String) throws -> [Data] {
//        guard let key = keysByAddress[account.address] else {
//            throw KeyStore.Error.accountNotFound
//        }
//        return try key.signHashes(data, password: password)
//    }
    
    // MARK: Helpers
    
    private func makeAccountURL(for keystoreKey: KeystoreKey) -> URL {
        var urlStr = generateFileName(address: keystoreKey.address)
        if keystoreKey.type == .hierarchicalDeterministicWallet {
            urlStr = "HD-" + urlStr
        }
        return keyDirectory.appendingPathComponent(urlStr)
    }
    
    /// Saves the account to the given directory.
    private func save(account: Account, in directory: URL) throws {
        guard let key = keysByAddress[account.address] else {
            fatalError("Missing account key")
        }
        try save(key: key, to: account.url)
    }
    
    /// Generates a unique file name for an address.
    func generateFileName(address: Address, date: Date = Date(), timeZone: TimeZone = .current) -> String {
        // keyFileName implements the naming convention for keyfiles:
        // UTC--<created_at UTC ISO8601>-<address hex>
        return "UTC--\(filenameTimestamp(for: date, in: timeZone))--\(address.data.hexString)"
    }
    
    private func filenameTimestamp(for date: Date, in timeZone: TimeZone = .current) -> String {
        var tz = ""
        let offset = timeZone.secondsFromGMT()
        if offset == 0 {
            tz = "Z"
        } else {
            tz = String(format: "%03d00", offset/60)
        }
        
        let components = Calendar(identifier: .iso8601).dateComponents(in: timeZone, from: date)
        return String(format: "%04d-%02d-%02dT%02d-%02d-%02d.%09d%@", components.year!, components.month!, components.day!, components.hour!, components.minute!, components.second!, components.nanosecond!, tz)
    }
    
    private func save(key: KeystoreKey, to url: URL) throws {
        let json = try JSONEncoder().encode(key)
        try json.write(to: url, options: [.atomicWrite])
    }
    
    
    internal func keychainKey(for account: Account) -> String {
        switch account.type {
        case .encryptedKey:
            return account.address.description.lowercased()
        case .hierarchicalDeterministicWallet:
            return account.address.description.lowercased()
        }
    }
    
    
    
    func convertPrivateKeyToKeystoreFile(privateKey: String, passphrase: String) -> Result<[String: Any], KeystoreError> {
        guard let data = Data(hexString: privateKey) else {
            return .failure(KeystoreError.failedToImportPrivateKey)
        }
        do {
            let key = try KeystoreKey(password: passphrase, key: data)
            let data = try JSONEncoder().encode(key)
            let dict = try JSONSerialization.jsonObject(with: data, options: []) as! [String: Any]
            return .success(dict)
        } catch {
            return .failure(KeystoreError.failedToImportPrivateKey)
        }
    }
    
    
    //MARK: - 密码操作
    @discardableResult
    func setPassword(_ password: String, for account: Account) -> Bool {
        return keychain.set(password, forKey: keychainKey(for: account), withAccess: defaultKeychainAccess)
    }
    func getPassword(for account: Account) -> String? {
        let kck = keychainKey(for: account)
        let pw = keychain.get(kck)
        print(kck + "密码是：" + pw!)
        return pw
    }
    
    //MARK: - 钱包名称操作
    @discardableResult
    func setWalletName(_ walletName: String, for account: Account) -> Bool {
        return keychain.set(walletName, forKey: keychainKey(for: account) + "walletName", withAccess: defaultKeychainAccess)
    }
    func getWalletName(for account: Account) -> String? {
        let kck = keychainKey(for: account) + "walletName"
        var walletName = keychain.get(kck)
        if walletName == nil {
            walletName = "钱包"
        }
        print(kck)
        return walletName
    }
    
    //MARK: - 钱包图片操作
    @discardableResult
    func setHeadImageName(_ walletName: String, for account: Account) -> Bool {
        return keychain.set(walletName, forKey: keychainKey(for: account) + "headImageName", withAccess: defaultKeychainAccess)
    }
    func getHeadImageName(for account: Account) -> String? {
        let kck = keychainKey(for: account) + "headImageName"
        var walletName = keychain.get(kck)
        if walletName == nil {
            walletName = "my_cell_coin"
        }
        return walletName
    }
    
    //MARK: - eth交易
    public func signTransaction(_ rawTransaction: RawTransaction, privateKey: Data, chainID: Int) throws -> String {
        let signTransaction = SignTransaction(
            rawTransaction: rawTransaction,
            gasPrice: Converter.toWei(GWei: Gas.price.value),
            gasLimit: Gas.limit.value
        )
        let signer = EIP155Signer(chainID: chainID)
        let rawData = try signer.sign(signTransaction, privateKey: privateKey)
        return rawData.toHexString().appending0xPrefix
    }

    //MARK: - Fuli交易
    public func signTransaction(_ rawTransaction: RawTransaction, gasLimit: Int, privateKey: Data, chainID: Int) throws -> String {
        let signTransaction = SignTransaction(
            rawTransaction: rawTransaction,
            gasPrice: Converter.toWei(GWei: Gas.price.value),
            gasLimit: gasLimit
        )
        let signer = EIP155Signer(chainID: chainID)
        let rawData = try signer.sign(signTransaction, privateKey: privateKey)
        return rawData.toHexString().appending0xPrefix
    }
}



extension KeyStore {
    public enum Error: Swift.Error {
        case accountAlreadyExists
        case accountNotFound
    }
}
