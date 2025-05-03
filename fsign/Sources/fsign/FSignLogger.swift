//
//  File.swift
//  FSign
//
//  Created by 이지안 on 5/3/25.
//

import Foundation

// import OSLog

internal struct FSignLogger {
    let verbose: Bool
    // private let logger = Logger(subsystem: "com.yourcompany.fsign", category: "signing") // Example using os.log

    func log(_ message: String, verboseOnly: Bool = false) {
        if verbose || !verboseOnly {
            print("[fsign] \(message)")
            // logger.log("\(message)") 
        } else if verboseOnly {
             // logger.debug("\(message)")
        }
    }
}
