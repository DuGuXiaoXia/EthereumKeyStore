import Foundation

import TrezorCrypto



// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
public final class Mnemonic {
    public enum Strength: Int {
        case normal = 128
        case hight = 256
    }
    
    public static func create(strength: Strength = .normal, language: WordList = .english) -> String {
        let byteCount = strength.rawValue / 8
        
        var bytes = Data(count: byteCount)
        _ = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, byteCount, $0) }
        return create(entropy: bytes, language: language)
    }
    
    public static func create(entropy: Data, language: WordList = .english) -> String {
        let entropybits = String(entropy.flatMap { ("00000000" + String($0, radix: 2)).suffix(8) })
        let hashBits = String(entropy.sha256().flatMap { ("00000000" + String($0, radix: 2)).suffix(8) })
        let checkSum = String(hashBits.prefix((entropy.count * 8) / 32))
        
        let words = language.words
        let concatenatedBits = entropybits + checkSum
        
//        var mnemonic: [String] = []
        var string: String = ""
        for index in 0..<(concatenatedBits.count / 11) {
            let startIndex = concatenatedBits.index(concatenatedBits.startIndex, offsetBy: index * 11)
            let endIndex = concatenatedBits.index(startIndex, offsetBy: 11)
            let wordIndex = Int(strtoul(String(concatenatedBits[startIndex..<endIndex]), nil, 2))
//            mnemonic.append(String(words[wordIndex]))
            print(wordIndex)
            string.append(String(words[wordIndex]) + " ")
        }
        print(string)
//        string = "seat island donor wrist goat inherit toy total wrong palm arm belt"
//
//        string = "mutual mammal trick hub rifle property cherry offer around horn exhibit fluid"
        print("本次生成地址的助记词：" + string)
        return string
    }
    
    
    /// Generates a menmoic string with the given strength in bits.
    ///
    /// - Precondition: `strength` is a multiple of 32 between 128 and 256
    /// - Parameter strength: strength in bits
    /// - Returns: mnemonic string
    public static func generate(strength: Int) -> String {
        precondition(strength % 32 == 0 && strength >= 128 && strength <= 256)
        let rawString = mnemonic_generate(Int32(strength))!
        return String(cString: rawString)
    }
    
    /// Generates a mnemonic from seed data.
    ///
    /// - Precondition: the length of `data` is a multiple of 4 between 16 and 32
    /// - Parameter data: seed data for the mnemonic
    /// - Returns: mnemonic string
    public static func generate(from data: Data) -> String {
        precondition(data.count % 4 == 0 && data.count >= 16 && data.count <= 32)
        let rawString = data.withUnsafeBytes { dataPtr in
            mnemonic_from_data(dataPtr, Int32(data.count))!
        }
        return String(cString: rawString)
    }
    
    /// Determines if a mnemonic string is valid.
    ///
    /// - Parameter string: mnemonic string
    /// - Returns: `true` if the string is valid; `false` otherwise.
    public static func isValid(_ string: String) -> Bool {
        return mnemonic_check(string) != 0
    }
    
    /// Derives the wallet seed.
    ///
    /// - Parameters:
    ///   - mnemonic: mnemonic string
    ///   - passphrase: mnemonic passphrase
    /// - Returns: wallet seed
    public static func deriveSeed(mnemonic: String, passphrase: String) -> Data {
        precondition(passphrase.count <= 256, "Passphrase too long")
        var seed = Data(repeating: 0, count: 512 / 8)
        seed.withUnsafeMutableBytes { seedPtr in
            mnemonic_to_seed(mnemonic, passphrase, seedPtr, nil)
        }
        return seed
    }
}


extension Mnemonic {
    enum Error: Swift.Error {
        case invalidStrength
    }
}


