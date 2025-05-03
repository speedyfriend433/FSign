//
//  File.swift
//  FSign
//
//  Created by 이지안 on 5/3/25.
//

import Foundation
import ZIPFoundation

extension FSigner {

    // MARK: - File System Helpers

    internal func validateInputPaths(ipaPath: String, provisioningProfilePath: String, p12Path: String, outputIpaPath: String) throws {
        guard fileManager.fileExists(atPath: ipaPath) else { throw FSignError.ipaNotFound(path: ipaPath) }
        guard fileManager.fileExists(atPath: provisioningProfilePath) else { throw FSignError.provisioningProfileNotFound(path: provisioningProfilePath) }
        guard fileManager.fileExists(atPath: p12Path) else { throw FSignError.p12CertificateNotFound(path: p12Path) }

        let outputDir = URL(fileURLWithPath: outputIpaPath).deletingLastPathComponent()
        var isDir: ObjCBool = false
        guard fileManager.fileExists(atPath: outputDir.path, isDirectory: &isDir) && isDir.boolValue else {
            throw FSignError.outputDirectoryDoesNotExist(path: outputDir.path)
        }
    }

    internal func createTemporaryDirectory() throws -> URL {
        do {
            let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
                .appendingPathComponent("fsign_\(UUID().uuidString)")
            try fileManager.createDirectory(at: tempDir, withIntermediateDirectories: true, attributes: nil)
            logger.log("Created temporary directory: \(tempDir.relativePath)", verboseOnly: true)
            return tempDir
        } catch {
            throw FSignError.temporaryDirectoryCreationFailed(error)
        }
    }

    internal func unzipIpa(ipaPath: String, destination: URL) throws {
        let sourceUrl = URL(fileURLWithPath: ipaPath)
        do {
            // Ensure destination exists
            try fileManager.createDirectory(at: destination, withIntermediateDirectories: true, attributes: nil)
            // Unzip
            try fileManager.unzipItem(at: sourceUrl, to: destination)
            logger.log("Successfully unzipped \(sourceUrl.lastPathComponent) to \(destination.relativePath)", verboseOnly: true)
        } catch {
            throw FSignError.ipaUnzipFailed(error)
        }
    }

    internal func findAppBundle(in payloadDir: URL) throws -> URL {
        do {
            let contents = try fileManager.contentsOfDirectory(at: payloadDir, includingPropertiesForKeys: [.isDirectoryKey], options: .skipsHiddenFiles)
            guard let appBundle = contents.first(where: {
                $0.pathExtension == "app" && (try? $0.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true
            }) else {
                throw FSignError.appBundleNotFound(in: payloadDir)
            }
            logger.log("Found app bundle: \(appBundle.relativePath)", verboseOnly: true)
            return appBundle
        } catch let error as FSignError {
            throw error
        } catch {
            throw FSignError.appBundleNotFound(in: payloadDir)
        }
    }

    internal func zipOutputIpa(sourceDirectory: URL, outputPath: String) throws {
        let outputUrl = URL(fileURLWithPath: outputPath)
        try? fileManager.removeItem(at: outputUrl)
        logger.log("Preparing to zip contents of \(sourceDirectory.relativePath) to \(outputUrl.relativePath)", verboseOnly: true)

        do {
            try fileManager.zipItem(at: sourceDirectory, to: outputUrl, shouldKeepParent: false, compressionMethod: .deflate, progress: nil)
            logger.log("Successfully zipped contents to \(outputUrl.relativePath)", verboseOnly: true)
        } catch {
            throw FSignError.ipaZipFailed(error)
        }
    }

    internal func cleanup(temporaryDirectory: URL) throws {
        logger.log("Cleaning up temporary directory: \(temporaryDirectory.relativePath)")
        do {
            if fileManager.fileExists(atPath: temporaryDirectory.path) {
                try fileManager.removeItem(at: temporaryDirectory)
                logger.log("Successfully removed temporary directory.", verboseOnly: true)
            }
        } catch {
            logger.log("Warning: Failed to clean up temporary directory: \(error.localizedDescription)")
        }
    }
}
