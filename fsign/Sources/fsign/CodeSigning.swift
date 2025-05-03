//
//  File.swift
//  FSign
//
//  Created by 이지안 on 5/3/25.
//

import Foundation
import CoreServices

extension FSigner {

    // MARK: - Code Signing Logic

    internal func removeExistingSignature(codeSignaturePath: String, embeddedProfilePath: String) throws {
        logger.log("Attempting to remove existing signature components...", verboseOnly: true)
        do {
            let csUrl = URL(fileURLWithPath: codeSignaturePath)
            let ppUrl = URL(fileURLWithPath: embeddedProfilePath)

            if fileManager.fileExists(atPath: csUrl.path) {
                try fileManager.removeItem(at: csUrl)
                logger.log("  Removed existing _CodeSignature directory: \(csUrl.relativePath)", verboseOnly: true)
            } else {
                logger.log("  No existing _CodeSignature directory found.", verboseOnly: true)
            }
            if fileManager.fileExists(atPath: ppUrl.path) {
                 try fileManager.removeItem(at: ppUrl)
                 logger.log("  Removed existing embedded.mobileprovision: \(ppUrl.relativePath)", verboseOnly: true)
            } else {
                 logger.log("  No existing embedded.mobileprovision found.", verboseOnly: true)
            }
        } catch {
            let failedPath = fileManager.fileExists(atPath: codeSignaturePath) ? embeddedProfilePath : codeSignaturePath
            throw FSignError.removeSignatureFailed(path: failedPath, error)
        }
    }

    internal func embedNewProvisioningProfile(sourcePath: String, targetPath: String) throws {
        let sourceUrl = URL(fileURLWithPath: sourcePath)
        let targetUrl = URL(fileURLWithPath: targetPath)
        logger.log("Embedding profile from \(sourceUrl.relativePath) to \(targetUrl.relativePath)", verboseOnly: true)
        do {
            try fileManager.copyItem(at: sourceUrl, to: targetUrl)
            logger.log("  Successfully embedded provisioning profile.", verboseOnly: true)
        } catch {
            throw FSignError.embedProvisioningProfileFailed(error)
        }
    }

    internal func writeEntitlements(_ entitlements: [String: Any], to path: String) throws {
        let url = URL(fileURLWithPath: path)
        logger.log("Writing entitlements to: \(url.relativePath)", verboseOnly: true)
        if logger.verbose {
             do {
                 let jsonData = try JSONSerialization.data(withJSONObject: entitlements, options: [.prettyPrinted, .sortedKeys])
                 let jsonString = String(data: jsonData, encoding: .utf8) ?? "Could not serialize entitlements to JSON"
                 logger.log("--- Begin Entitlements ---\n\(jsonString)\n--- End Entitlements ---", verboseOnly: true)
             } catch {
                  logger.log("Warning: Could not serialize entitlements to JSON for logging: \(error)", verboseOnly: true)
             }
        }

        do {
            let data = try PropertyListSerialization.data(fromPropertyList: entitlements, format: .xml, options: 0)
            try data.write(to: url)
            logger.log("  Successfully wrote entitlements file.", verboseOnly: true)
        } catch {
            throw FSignError.entitlementsWriteFailed(path: path, error)
        }
    }

    /// Recursively finds and signs components within an app bundle.
    internal func signComponentTree(
        appBundleUrl: URL,
        identitySHA1: String,
        entitlementsPath: String,
        signingOptions: SigningOptions
    ) throws {
        logger.log("Finding signable components within \(appBundleUrl.relativePath)...", verboseOnly: true)
        let itemsToSign = try findSignableItems(in: appBundleUrl)

        logger.log("Found \(itemsToSign.count) items to sign.")
        guard !itemsToSign.isEmpty else {
             logger.log("Warning: No signable items found within \(appBundleUrl.path). This might indicate an empty or invalid bundle.", verboseOnly: false)
             return
        }

        for itemUrl in itemsToSign {
            let needsEntitlements: Bool
            let pathExtension = itemUrl.pathExtension.lowercased()

            if itemUrl == appBundleUrl || ["appex", "watchapp", "watchkitextension", "messagesextension"].contains(pathExtension) {
                 needsEntitlements = true
                 logger.log("  Item \(itemUrl.lastPathComponent) requires entitlements.", verboseOnly: true)
            } else {
                 needsEntitlements = false
                 logger.log("  Item \(itemUrl.lastPathComponent) does not require main entitlements.", verboseOnly: true)
            }

            logger.log("Signing component: \(itemUrl.relativePath)")
            try executeCodesign(
                identitySHA1: identitySHA1,
                entitlementsPath: needsEntitlements ? entitlementsPath : nil,
                path: itemUrl.path,
                timestamp: signingOptions.useTimestamp,
                hardenedRuntime: signingOptions.useHardenedRuntime,
                digestAlgorithm: signingOptions.digestAlgorithm
            )
        }
        logger.log("Finished signing all \(itemsToSign.count) components.", verboseOnly: true)
    }

    /// Finds all components within a bundle that require code signing.
    /// Returns an array of URLs sorted by path depth (deepest first) for correct signing order.
    internal func findSignableItems(in bundleUrl: URL) throws -> [URL] {
        var collectedURLs: Set<URL> = []
        let resourceKeys: [URLResourceKey] = [.isDirectoryKey, .isExecutableKey, .contentTypeKey, .isSymbolicLinkKey]
        let mainExecutableName = try? getMainExecutableName(appBundleUrl: bundleUrl)
        logger.log("Scanning for signable items, Main Executable: \(mainExecutableName ?? "Not Found")", verboseOnly: true)

        let bundleExtensions: Set<String> = ["app", "appex", "plugin", "framework", "xpc", "bundle", "service", "dylib", "so", "vis", "saver", "qlgenerator", "mdimporter", "automator", "action", "ibplugin", "watchapp", "watchkitextension", "xcframework"]
        let codeUTIs: Set<String> = [
            kUTTypeMachOBundle as String,
            kUTTypeMachOExecutable as String,
            kUTTypeUnixExecutable as String,
            "com.apple.mach-o-dylib",
            kUTTypeApplicationBundle as String,
            kUTTypeFramework as String,
            kUTTypeBundle as String,
            kUTTypePluginBundle as String
        ]
        let excludedDirNames: Set<String> = ["Headers", "PrivateHeaders", "Modules", "Resources", "_CodeSignature", "Support Files"]

        guard let enumerator = fileManager.enumerator(at: bundleUrl,
                                               includingPropertiesForKeys: resourceKeys,
                                               options: [.skipsHiddenFiles])
        else {
            throw FSignError.findSignableComponentsFailed(NSError(domain: "FSign", code: -1, userInfo: [NSLocalizedDescriptionKey:"Failed to create file enumerator for \(bundleUrl.path)."]))
        }

        for case let url as URL in enumerator {
            if url.path.contains("/..namedfork/rsrc") {
                enumerator.skipDescendants()
                continue
            }
            if excludedDirNames.contains(url.lastPathComponent) {
                 logger.log("    Skipping descendants of excluded directory: \(url.relativePath)", verboseOnly: true)
                 enumerator.skipDescendants()
                 continue
            }


            do {
                let resourceValues = try url.resourceValues(forKeys: Set(resourceKeys))
                let isDirectory = resourceValues.isDirectory ?? false
                let isSymlink = resourceValues.isSymbolicLink ?? false
                let pathExtension = url.pathExtension.lowercased()
                let contentType = resourceValues.contentType


                // --- Case 1: Nested Bundles (Frameworks, Plugins, Appex, etc.) ---
                if isDirectory && (bundleExtensions.contains(pathExtension) || (contentType != nil && contentType!.conforms(to: kUTTypeBundle))) {
                    collectedURLs.insert(url)
                    logger.log("    Found bundle: \(url.relativePath) (Ext: \(pathExtension), UTI: \(contentType?.identifier ?? "N/A"))", verboseOnly: true)
                    enumerator.skipDescendants()
                }
                // --- Case 2: Binaries, Libraries, and Main Executable (Files) ---
                else if !isDirectory && !isSymlink {
                    let isExecutable = resourceValues.isExecutable ?? false
                    let isMainExecutable = (url.lastPathComponent == mainExecutableName && url.deletingLastPathComponent() == bundleUrl)

                    var shouldSign = false
                    if isMainExecutable {
                        shouldSign = true
                        logger.log("    Found main executable: \(url.relativePath)", verboseOnly: true)
                    } else if isExecutable {
                        if let uti = contentType, codeUTIs.contains(uti.identifier) {
                            shouldSign = true
                            logger.log("    Found executable code (UTI): \(url.relativePath)", verboseOnly: true)
                        } else if pathExtension == "dylib" {
                           shouldSign = true
                           logger.log("    Found executable code (dylib ext): \(url.relativePath)", verboseOnly: true)
                        } else {
                             logger.log("    Skipping executable (non-code/unknown UTI?): \(url.relativePath) UTI: \(contentType?.identifier ?? "N/A")", verboseOnly: true)
                        }
                    } else if let uti = contentType, uti.identifier == "com.apple.mach-o-dylib" {
                        shouldSign = true
                         logger.log("    Found non-executable dylib (UTI): \(url.relativePath)", verboseOnly: true)
                    }

                    if shouldSign {
                        if url.lastPathComponent != "Info.plist" && url.lastPathComponent != "PkgInfo" {
                            collectedURLs.insert(url)
                        } else {
                             logger.log("    Skipping resource file: \(url.relativePath)", verboseOnly: true)
                        }
                    }
                }
                // --- Case 3: Symbolic Links ---
            } catch {
                 logger.log("Warning: Could not get resource values for \(url.relativePath): \(error.localizedDescription)", verboseOnly: true)
            }
        }
        
         if !collectedURLs.contains(bundleUrl) && fileManager.fileExists(atPath: bundleUrl.path) {
              collectedURLs.insert(bundleUrl)
              logger.log("    Ensuring main bundle is included: \(bundleUrl.relativePath)", verboseOnly: true)
         }

        var items = Array(collectedURLs)
        items.sort { $0.path.count > $1.path.count }

        logger.log("Final signing order calculated for \(items.count) items:", verboseOnly: true)
        if logger.verbose { items.forEach { logger.log("  -> \($0.relativePath)", verboseOnly: true)} }

        return items
    }


    /// Executes the `codesign` command-line tool.
    internal func executeCodesign(
        identitySHA1: String,
        entitlementsPath: String?,
        path: String,
        timestamp: Bool,
        hardenedRuntime: Bool,
        digestAlgorithm: String
    ) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")

        var arguments = [
            "--force",
            "--sign", identitySHA1,
            "--verbose=4",
            "--digest-algorithm", digestAlgorithm,
        ]

        var options: [String] = []
        if hardenedRuntime {
            options.append("runtime")
        }
        if !options.isEmpty {
            arguments.append("--options=\(options.joined(separator: ","))")
             logger.log("    Using options: \(options.joined(separator: ","))", verboseOnly: true)
        }a
        if timestamp {
            arguments.append("--timestamp")
             logger.log("    Including secure timestamp.", verboseOnly: true)
        } else {
             logger.log("    Skipping timestamp.", verboseOnly: true)
        }
        if let entitlements = entitlementsPath {
            guard fileManager.fileExists(atPath: entitlements) else {
                throw FSignError.entitlementsGenerationFailed("Entitlements file expected but not found at \(entitlements) for signing \(path)")
            }
             arguments.append(contentsOf: ["--entitlements", entitlements])
             logger.log("    Using entitlements: \(URL(fileURLWithPath: entitlements).relativePath)", verboseOnly: true)
        } else {
            logger.log("    Signing without specific entitlements file.", verboseOnly: true)
        }

        arguments.append(path)

        process.arguments = arguments

        let stdOutPipe = Pipe()
        let stdErrPipe = Pipe()
        process.standardOutput = stdOutPipe
        process.standardError = stdErrPipe

        let commandString = "/usr/bin/codesign \(arguments.joined(separator: " "))"
        logger.log("    Executing: \(commandString)", verboseOnly: true)

        do {
            try process.run()
            process.waitUntilExit()

            let stdOutData = stdOutPipe.fileHandleForReading.readDataToEndOfFile()
            let stdErrData = stdErrPipe.fileHandleForReading.readDataToEndOfFile()
            let stdOut = String(data: stdOutData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let stdErr = String(data: stdErrData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if process.terminationStatus != 0 {
                logger.log("CodeSign Error Output (stderr):\n---\n\(stdErr)\n---", verboseOnly: false)
                logger.log("CodeSign Standard Output (stdout):\n---\n\(stdOut)\n---", verboseOnly: false)
                let errorOutput = stdErr.isEmpty ? stdOut : stdErr
                throw FSignError.codeSignExecutionFailed(command: commandString,
                                                       exitCode: process.terminationStatus,
                                                       errorOutput: errorOutput)
            } else {
                 if !stdOut.isEmpty { logger.log("    codesign stdout: \(stdOut)", verboseOnly: true) }
                 if !stdErr.isEmpty { logger.log("    codesign stderr: \(stdErr)", verboseOnly: true) }
                 logger.log("    Successfully signed \(URL(fileURLWithPath: path).lastPathComponent).", verboseOnly: true)
            }

        } catch let error as FSignError {
            throw error
        } catch {
             throw FSignError.codeSignExecutionFailed(command: commandString,
                                                   exitCode: -1,
                                                   errorOutput: "Process.run() failed for codesign: \(error.localizedDescription)")
        }
    }


    /// Verifies the signature of the application bundle using `codesign --verify`.
    internal func verifySignature(bundlePath: String) throws {
        let bundleUrl = URL(fileURLWithPath: bundlePath)
        logger.log("Verifying signature for: \(bundleUrl.relativePath)...")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")

        /// --verify: Perform verification
        // --deep: Check nested code content like frameworks and helpers. Crucial.
        /// --strict: Apply stricter checks. Recommended for ensuring validity.
        /// --verbose=4: Get detailed output, especially on failure.
        process.arguments = ["--verify", "--deep", "--strict", "--verbose=4", bundlePath]

        let stdOutPipe = Pipe()
        let stdErrPipe = Pipe()
        process.standardOutput = stdOutPipe
        process.standardError = stdErrPipe

        let commandString = "/usr/bin/codesign \(process.arguments!.joined(separator: " "))"
        logger.log("    Executing: \(commandString)", verboseOnly: true)

        do {
            try process.run()
            process.waitUntilExit()

            let stdOutData = stdOutPipe.fileHandleForReading.readDataToEndOfFile()
            let stdErrData = stdErrPipe.fileHandleForReading.readDataToEndOfFile()
            let stdOut = String(data: stdOutData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let stdErr = String(data: stdErrData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

            if process.terminationStatus != 0 {
                logger.log("Verification Error Output (stderr):\n---\n\(stdErr)\n---", verboseOnly: false)
                logger.log("Verification Standard Output (stdout):\n---\n\(stdOut)\n---", verboseOnly: false)
                 let errorOutput = stdErr.isEmpty ? stdOut : stdErr
                throw FSignError.signatureVerificationFailed(command: commandString,
                                                       exitCode: process.terminationStatus,
                                                       errorOutput: errorOutput)
            } else {
                 if !stdOut.isEmpty { logger.log("    codesign verify stdout: \(stdOut)", verboseOnly: true) }
                 if !stdErr.isEmpty { logger.log("    codesign verify stderr: \(stdErr)", verboseOnly: true) }
                 logger.log("Signature verification successful for \(bundleUrl.lastPathComponent).")
            }
        } catch let error as FSignError {
             throw error 
        } catch {
            throw FSignError.signatureVerificationFailed(command: commandString, exitCode: -1, errorOutput: "Process.run() for verification failed: \(error.localizedDescription)")
        }
    }
}
