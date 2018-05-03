import Foundation

enum ImportType {
    case keystore(string: String, password: String)
    case privateKey(privateKey: String, password: String)
    case mnemonic(words: [String], password: String)
    case watch(address: Address)
}

