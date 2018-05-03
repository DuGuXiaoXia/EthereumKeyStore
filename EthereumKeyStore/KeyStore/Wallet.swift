import TrezorCrypto


struct Wallet {
    struct Keys {
        static let walletPrivateKey = "wallet-private-key-"
        static let walletHD = "wallet-hd-wallet-"
        static let address = "wallet-address-"
    }
    
    let type: WalletType
    
    var address: Address {
        switch type {
        case .privateKey(let account):
            return account.address
        case .hd(let account):
            return account.address
        case .address(let address):
            return address
        }
    }
    
    
    var description: String {
        switch self.type {
        case .privateKey(let account):
            return account.address.description
        case .hd(let account):
            return account.address.description
        case .address(let address):
            return address.description
        }
    }
    
//    var walletName: String {
//        return (Coordinator.shared.keystore?.getWalletName(for: (Coordinator.shared.keystore?.account(for: self.address))!))!
//    }
//    var walletHeadImageName: String {
//        return (Coordinator.shared.keystore?.getHeadImageName(for: (Coordinator.shared.keystore?.account(for: self.address))!))!
//    }
    var walletName: String
    var walletHeadImageName: String 
    
    
}

public final class WalletCreate {
    
    public static let defaultPath = "m/44'/60'/0'/0/0"
    
    /// Wallet seed.
    public var seed: Data
    
    /// Mnemonic word list.
    public var mnemonic: String
    
    /// Mnemonic passphrase.
    public var passphrase: String
    
    /// Derivation path.
    public var path: String
    
    /// Initializes a wallet from a mnemonic string and a passphrase.
    public init(mnemonic: String, passphrase: String = "", path: String = WalletCreate.defaultPath) {
        seed = Mnemonic.deriveSeed(mnemonic: mnemonic, passphrase: "")
        self.mnemonic = mnemonic
        self.passphrase = ""
        self.path = path
    }
    

    required public init?(coder aDecoder: NSCoder!) {
        fatalError("This class doesn't support NSCoding.")
    }
    
    
    private func getDerivationPath(for index: Int) -> DerivationPath {
        guard let path = DerivationPath(path.replacingOccurrences(of: "x", with: String(index))) else {
            preconditionFailure("Invalid derivation path string")
        }
        return path
    }
    
    private func getNode(for derivationPath: DerivationPath) -> HDNode {
        var node = HDNode()
        
        hdnode_from_seed(seed.bytes, Int32(seed.count), "secp256k1", &node)
        for index in derivationPath.indices {
            hdnode_private_ckd(&node, index.derivationIndex)
           
        }
        
        return node
    }
    
    /// Generates the key at the specified derivation path index.
    public func getKey(at index: Int) -> HDKey {
        let node = getNode(for: getDerivationPath(for: index))
        return HDKey(node: node)
    }
    //MARK: - //********************************************//
    
    
}

