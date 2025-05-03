//
//  File.swift
//  FSign
//
//  Created by 이지안 on 5/3/25.
//

import Foundation
import CoreServices

extension FSigner {

    // MARK: - Info.plist Handling

    internal func updateInfoPlist(path: String, newBundleID: String?, newDisplayName: String?) throws {
        logger.log("Checking Info.plist for updates at: \(URL(fileURLWithPath: path).relativePath)", verboseOnly: true)
        guard let plistData = fileManager.contents(atPath: path) else {
            throw FSignError.infoPlistReadFailed(path: path)
        }

        do {
            var format = PropertyListSerialization.PropertyListFormat.xml
            var plist = try PropertyListSerialization.propertyList(from: plistData, options: .mutableContainersAndLeaves, format: &format)

            guard var plistDict = plist as? [String: Any] else {
                throw FSignError.infoPlistParsingError
            }

            var modified = false
            if let bundleID = newBundleID {
                if (plistDict[kCFBundleIdentifierKey as String] as? String) != bundleID {
                    plistDict[kCFBundleIdentifierKey as String] = bundleID
                    logger.log("  Set CFBundleIdentifier to: \(bundleID)")
                    modified = true
                }
            }
            if let displayName = newDisplayName {
                 if (plistDict[kCFBundleDisplayNameKey as String] as? String) != displayName {
                    plistDict[kCFBundleDisplayNameKey as String] = displayName
                    logger.log("  Set CFBundleDisplayName to: \(displayName)")
                    modified = true
                 }
                if let currentBundleName = plistDict[kCFBundleNameKey as String] as? String {
                     let expectedBundleName = displayName.replacingOccurrences(of: " ", with: "")
                    if currentBundleName != expectedBundleName {
                        plistDict[kCFBundleNameKey as String] = expectedBundleName
                         logger.log("  Set CFBundleName to: \(expectedBundleName)")
                         modified = true
                    }
                }
            }

            if modified {
                logger.log("Info.plist was modified, writing changes...", verboseOnly: true)
                let updatedPlistData = try PropertyListSerialization.data(fromPropertyList: plistDict, format: format, options: 0)
                try updatedPlistData.write(to: URL(fileURLWithPath: path))
                logger.log("Successfully updated Info.plist.", verboseOnly: true)
            } else {
                 logger.log("Info.plist already up-to-date. No changes needed.", verboseOnly: true)
            }

        } catch let error as FSignError {
             throw error
        } catch {
            throw FSignError.infoPlistWriteFailed(path: path, error)
        }
    }

    /// Gets the CFBundleExecutable value from the app bundle's Info.plist.
    internal func getMainExecutableName(appBundleUrl: URL) throws -> String {
        let infoPlistUrl = appBundleUrl.appendingPathComponent("Info.plist")
        logger.log("Reading main executable name from: \(infoPlistUrl.relativePath)", verboseOnly: true)
        guard let plistData = fileManager.contents(atPath: infoPlistUrl.path) else {
             throw FSignError.infoPlistReadFailed(path: infoPlistUrl.path)
        }

        var format = PropertyListSerialization.PropertyListFormat.xml
        guard let plist = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: &format) as? [String: Any] else {
            throw FSignError.infoPlistParsingError
        }
        guard let executableName = plist[kCFBundleExecutableKey as String] as? String else {
             throw FSignError.mainExecutableNotFoundInPlist(path: infoPlistUrl.path)
        }
         logger.log("Found main executable name: \(executableName)", verboseOnly: true)
        return executableName
    }
}
