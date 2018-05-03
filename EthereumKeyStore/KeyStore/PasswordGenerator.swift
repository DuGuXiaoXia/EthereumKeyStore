//
//  PasswordGenerator.swift
//  welfarecoin
//
//  Created by alex on 2018/3/29.
//  Copyright © 2018年 http://kuaishangxian.com.cn/. All rights reserved.
//

import Foundation
import Security

struct PasswordGenerator {
    
    static func generateRandom() -> String {
        return PasswordGenerator.generateRandomString(bytesCount: 32)
    }
    
    static func generateRandomString(bytesCount: Int) -> String {
        var randomBytes = [UInt8](repeating: 0, count: bytesCount)
        let _ = SecRandomCopyBytes(kSecRandomDefault, bytesCount, &randomBytes)
        return randomBytes.map({ String(format: "%02hhx", $0) }).joined(separator: "")
    }
}
