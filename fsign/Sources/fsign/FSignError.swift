//
//  File.swift
//  FSign
//
//  Created by 이지안 on 5/3/25.
//

import Foundation
import Security

public enum FSignError: LocalizedError {
    case ipaNotFound(path: String)
    case provisioningProfileNotFound(path: String)
    case p12CertificateNotFound(path: String)
    case outputDirectoryDoesNotExist(path: String)
    case temporaryDirectoryCreationFailed(Error)
    case ipaUnzipFailed(Error)
    case payloadNotFound(in: URL)
    case appBundleNotFound(in: URL)
    case infoPlistReadFailed(path: String)
    case infoPlistWriteFailed(path: String, Error)
    case infoPlistParsingError
    case mainExecutableNotFoundInPlist(path: String)
    case provisioningProfileParsingFailed(reason: String)
    case cmsDecoderCreationFailed
    case cmsUpdateFailed(OSStatus)
    case cmsFinalizeFailed(OSStatus)
    case cmsContentExtractionFailed(OSStatus)
    case invalidProvisioningProfileFormat(String)
    case p12ImportFailed(OSStatus)
    case p12ParsingFailed(String)
    case identityNotFoundInP12
    case certificateExtractionFailed(OSStatus)
    case getCertSHA1Failed
    case removeSignatureFailed(path: String, Error)
    case embedProvisioningProfileFailed(Error)
    case entitlementsGenerationFailed(String)
    case entitlementsWriteFailed(path: String, Error)
    case codeSignExecutionFailed(command: String, exitCode: Int32, errorOutput: String)
    case signatureVerificationFailed(command: String, exitCode: Int32, errorOutput: String)
    case findSignableComponentsFailed(Error)
    case ipaZipFailed(Error)
    case cleanupFailed(Error)
    case securityError(status: OSStatus, message: String? = nil)
    case entitlementProcessingError(Error)

    private static func osStatusString(_ status: OSStatus) -> String {
        return (SecCopyErrorMessageString(status, nil) as String?) ?? "Unknown OSStatus"
    }

    public var errorDescription: String? {
        switch self {
        case .ipaNotFound(let path): return "IPA file not found at \(path)."
        case .provisioningProfileNotFound(let path): return "Provisioning profile file not found at \(path)."
        case .p12CertificateNotFound(let path): return "P12 certificate file not found at \(path)."
        case .outputDirectoryDoesNotExist(let path): return "Output directory does not exist at \(path)."
        case .temporaryDirectoryCreationFailed(let error): return "Failed to create temporary directory: \(error.localizedDescription)."
        case .ipaUnzipFailed(let error): return "Failed to unzip IPA: \(error.localizedDescription)."
        case .payloadNotFound(let url): return "Payload directory not found within extracted IPA at \(url.path)."
        case .appBundleNotFound(let url): return ".app bundle not found within Payload directory at \(url.path)."
        case .infoPlistReadFailed(let path): return "Failed to read Info.plist at \(path)."
        case .infoPlistWriteFailed(let path, let error): return "Failed to write Info.plist at \(path): \(error.localizedDescription)."
        case .infoPlistParsingError: return "Failed to parse Info.plist."
        case .mainExecutableNotFoundInPlist(let path): return "CFBundleExecutable key not found in Info.plist at \(path)."
        case .provisioningProfileParsingFailed(let reason): return "Failed to parse provisioning profile: \(reason)."
        case .cmsDecoderCreationFailed: return "Failed to create CMS decoder for provisioning profile."
        case .cmsUpdateFailed(let status): return "Failed to update CMS decoder with profile data. OSStatus: \(status) (\(osStatusString(status)))."
        case .cmsFinalizeFailed(let status): return "Failed to finalize CMS decoder for profile. OSStatus: \(status) (\(osStatusString(status)))."
        case .cmsContentExtractionFailed(let status): return "Failed to extract content from CMS profile. OSStatus: \(status) (\(osStatusString(status)))."
        case .invalidProvisioningProfileFormat(let detail): return "Invalid provisioning profile format: \(detail)."
        case .p12ImportFailed(let status): return "Failed to import P12 file. OSStatus: \(status) (\(osStatusString(status)))."
        case .p12ParsingFailed(let reason): return "Failed to parse P12 file: \(reason)."
        case .identityNotFoundInP12: return "No signing identity (certificate + private key) found in the P12 file."
        case .certificateExtractionFailed(let status): return "Failed to extract certificate (SecCertificate) from identity. OSStatus: \(status) (\(osStatusString(status)))."
        case .getCertSHA1Failed: return "Failed to calculate SHA1 hash of the certificate."
        case .removeSignatureFailed(let path, let error): return "Failed to remove existing signature component at \(path): \(error.localizedDescription)."
        case .embedProvisioningProfileFailed(let error): return "Failed to embed new provisioning profile: \(error.localizedDescription)."
        case .entitlementsGenerationFailed(let reason): return "Failed to generate entitlements: \(reason)."
        case .entitlementsWriteFailed(let path, let error): return "Failed to write entitlements file to \(path): \(error.localizedDescription)."
        case .codeSignExecutionFailed(let command, let exitCode, let errorOutput):
            return "Code signing command failed (Exit Code: \(exitCode)).\nCommand: \(command)\nOutput: \(errorOutput)"
        case .signatureVerificationFailed(let command, let exitCode, let errorOutput):
            return "Signature verification command failed (Exit Code: \(exitCode)).\nCommand: \(command)\nOutput: \(errorOutput)"
        case .findSignableComponentsFailed(let error): return "Failed to find signable components within the app bundle: \(error.localizedDescription)."
        case .ipaZipFailed(let error): return "Failed to re-zip the application into an IPA: \(error.localizedDescription)."
        case .cleanupFailed(let error): return "Failed to clean up temporary directory: \(error.localizedDescription)."
        case .securityError(let status, let message):
            let baseMessage = "A security framework error occurred. OSStatus: \(status) (\(osStatusString(status)))"
            return message != nil ? "\(baseMessage) - \(message!)" : baseMessage
        case .entitlementProcessingError(let error): return "Error during custom entitlement processing: \(error.localizedDescription)"
        }
    }
}
