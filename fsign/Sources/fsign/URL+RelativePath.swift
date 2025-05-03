//
//  File.swift
//  FSign
//
//  Created by 이지안 on 5/3/25.
//

import Foundation

internal extension URL {
    /// Provides a shorter path representation relative to common base directories for logging.
    var relativePath: String {
        let tempDir = NSTemporaryDirectory()
        let homeDir = FileManager.default.homeDirectoryForCurrentUser.path

        if self.path.hasPrefix(tempDir) {
            return self.path.replacingOccurrences(of: tempDir, with: "{TMP}/")
        }
        if self.path.hasPrefix(homeDir) {
            return self.path.replacingOccurrences(of: homeDir, with: "~")
        }
        return self.path 
    }
}
