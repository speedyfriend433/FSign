//
//  File.swift
//  FSign
//
//  Created by 이지안 on 5/3/25.
//

import Foundation
import Security
import CommonCrypto

extension FSigner {

    // MARK: - P12 and Certificate Handling

    internal func extractIdentity(p12Path: String, password: String) throws -> SecIdentity {
        let p12Url = URL(fileURLWithPath: p12Path)
        logger.log("Reading P12 data from \(p12Url.relativePath)", verboseOnly: true)
        let p12Data: Data
        do {
            p12Data = try Data(contentsOf: p12Url)
        } catch {
            throw FSignError.p12ParsingFailed("Could not read P12 file data: \(error.localizedDescription)")
        }

        let options = [kSecImportExportPassphrase as String: password] as CFDictionary

        var items: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options, &items)

        guard status == errSecSuccess else {
            throw FSignError.p12ImportFailed(status)
        }
        guard let importedItems = items as? [[String: Any]] else {
            throw FSignError.p12ParsingFailed("Could not cast imported P12 items array.")
        }
        guard !importedItems.isEmpty else {
            throw FSignError.p12ParsingFailed("No items found in P12 file.")
        }

        logger.log("Successfully imported P12 data. Found \(importedItems.count) item(s).", verboseOnly: true)

        for item in importedItems {
            if let identity = item[kSecImportItemIdentity as String] {
                if CFGetTypeID(identity as CFTypeRef) == SecIdentityGetTypeID() {
                     logger.log("Found SecIdentityRef in P12 item.", verboseOnly: true)
                     return (identity as! SecIdentity)
                } else {
                     logger.log("Warning: Found item with kSecImportItemIdentity key, but it's not a SecIdentityRef.", verboseOnly: false)
                }
            }
        }
        throw FSignError.identityNotFoundInP12
    }

    internal func extractCertificate(from identity: SecIdentity) throws -> SecCertificate {
        var certificate: SecCertificate?
        let status = SecIdentityCopyCertificate(identity, &certificate)
        guard status == errSecSuccess, let cert = certificate else {
            logger.log("Failed to copy certificate from identity. OSStatus: \(status)", verboseOnly: false)
            throw FSignError.certificateExtractionFailed(status)
        }
        logger.log("Successfully extracted SecCertificateRef from identity.", verboseOnly: true)
        return cert
    }

    internal func getCertificateSHA1Hash(certificate: SecCertificate) throws -> String {
        let certData = SecCertificateCopyData(certificate) as Data
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))

        certData.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Void in
            _ = CC_SHA1(bytes.baseAddress, CC_LONG(certData.count), &digest)
        }

        let sha1 = digest.map { String(format: "%02hhx", $0) }.joined()
        logger.log("Calculated certificate SHA1: \(sha1)", verboseOnly: true)
        return sha1
    }
}
