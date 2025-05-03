import Foundation
import Security

public final class FSigner {

    internal let fileManager: FileManager
    internal var temporaryDirectory: URL?
    internal let logger: FSignLogger

    /// Initializes the FSigner.
    /// - Parameters:
    ///   - fileManager: The `FileManager` instance to use. Defaults to `.default`.
    ///   - verbose: If `true`, prints detailed logging information during the signing process. Defaults to `false`.
    public init(fileManager: FileManager = .default, verbose: Bool = false) {
        self.fileManager = fileManager
        self.logger = FSignLogger(verbose: verbose)
        logger.log("FSigner initialized. Verbose logging: \(verbose).", verboseOnly: true)
    }

    deinit {
        if let tempDir = temporaryDirectory {
            logger.log("FSigner deinit: Cleaning up temporary directory \(tempDir.relativePath)...", verboseOnly: true)
            try? cleanup(temporaryDirectory: tempDir)
        }
    }

    /// Signs an iOS application package (IPA).
    ///
    /// This function orchestrates the entire resigning process: unzipping the IPA,
    /// modifying bundle ID/display name (if requested), replacing the provisioning profile,
    /// applying entitlements (potentially modified by a processor), signing all necessary
    /// components using the provided identity, verifying the signature, and re-zipping the IPA.
    ///
    /// - Parameters:
    ///   - ipaPath: Path to the input IPA file.
    ///   - provisioningProfilePath: Path to the .mobileprovision file to embed.
    ///   - p12Path: Path to the P12 certificate file containing the signing identity (certificate + private key).
    ///   - p12Password: Password for the P12 file.
    ///   - outputIpaPath: Path where the newly signed IPA should be saved.
    ///   - newBundleID: (Optional) A new bundle identifier to set in the Info.plist. If `nil`, the original ID is kept.
    ///   - newDisplayName: (Optional) A new display name to set in the Info.plist (`CFBundleDisplayName` and potentially `CFBundleName`). If `nil`, the original name(s) are kept.
    ///   - options: Configuration for the signing process (timestamp, hardened runtime, digest algorithm). Defaults to `SigningOptions()`.
    ///   - entitlementProcessor: (Optional) A closure that receives the base entitlements from the profile and returns the entitlements to be used for signing. Allows modification (e.g., setting `get-task-allow`).
    /// - Throws: An `FSignError` if any step of the signing process fails.
    public func sign(
        ipaPath: String,
        provisioningProfilePath: String,
        p12Path: String,
        p12Password: String,
        outputIpaPath: String,
        newBundleID: String? = nil,
        newDisplayName: String? = nil,
        options: SigningOptions = SigningOptions(),
        entitlementProcessor: EntitlementProcessor? = nil
    ) throws {
        logger.log("Starting signing process for IPA: \(URL(fileURLWithPath: ipaPath).lastPathComponent)")
        logger.log("Using Profile: \(URL(fileURLWithPath: provisioningProfilePath).lastPathComponent)", verboseOnly: true)
        logger.log("Using P12: \(URL(fileURLWithPath: p12Path).lastPathComponent)", verboseOnly: true)
        logger.log("Output Path: \(URL(fileURLWithPath: outputIpaPath).relativePath)")
        if let bid = newBundleID { logger.log("New Bundle ID: \(bid)") }
        if let name = newDisplayName { logger.log("New Display Name: \(name)") }
        logger.log("Signing Options: Timestamp=\(options.useTimestamp), HardenedRuntime=\(options.useHardenedRuntime), Digest=\(options.digestAlgorithm)", verboseOnly: true)

        // 1. --- Input Validation ---
        logger.log("Validating input paths...", verboseOnly: true)
        try validateInputPaths(ipaPath: ipaPath, provisioningProfilePath: provisioningProfilePath, p12Path: p12Path, outputIpaPath: outputIpaPath)

        // 2. --- Setup Temporary Directory ---
        temporaryDirectory = try createTemporaryDirectory()
        guard let tempDir = temporaryDirectory else {
            // Should not happen if createTemporaryDirectory succeeded without throwing
            throw FSignError.temporaryDirectoryCreationFailed(NSError(domain: "FSign", code: -1, userInfo: [NSLocalizedDescriptionKey: "Temporary directory URL is nil after creation."]))
        }
        let extractedIpaDir = tempDir.appendingPathComponent("extracted_ipa", isDirectory: true)

        defer {
            if let tempDir = temporaryDirectory {
                try? cleanup(temporaryDirectory: tempDir)
                self.temporaryDirectory = nil
            }
        }

        // 3. --- Unzip IPA ---
        logger.log("Unzipping IPA...")
        try unzipIpa(ipaPath: ipaPath, destination: extractedIpaDir)

        // 4. --- Locate App Bundle ---
        logger.log("Locating Payload and .app bundle...")
        let payloadDir = extractedIpaDir.appendingPathComponent("Payload", isDirectory: true)
        guard fileManager.fileExists(atPath: payloadDir.path) else {
            throw FSignError.payloadNotFound(in: extractedIpaDir)
        }
        let appBundleUrl = try findAppBundle(in: payloadDir)
        logger.log("Found app bundle at: \(appBundleUrl.relativePath)")

        // 5. --- Parse Provisioning Profile & Extract Base Entitlements ---
        logger.log("Parsing provisioning profile...")
        let profileInfo = try parseProvisioningProfile(path: provisioningProfilePath)
        let baseEntitlements = try extractEntitlements(from: profileInfo)

        // 6. --- Apply Entitlement Processor (if provided) ---
        let finalEntitlements: [String: Any]
        if let processor = entitlementProcessor {
            logger.log("Applying custom entitlement processor...")
            do {
                finalEntitlements = try processor(baseEntitlements)
                logger.log("Custom entitlement processor applied successfully.")
            } catch {
                 throw FSignError.entitlementProcessingError(error)
            }
        } else {
            finalEntitlements = baseEntitlements
            logger.log("No custom entitlement processor provided, using base entitlements.", verboseOnly: true)
        }

        // 7. --- Parse P12 Certificate & Get Identity/SHA1 ---
        logger.log("Parsing P12 certificate...")
        let identity: SecIdentity = try extractIdentity(p12Path: p12Path, password: p12Password)
        let certificate: SecCertificate = try extractCertificate(from: identity)
        let certificateSHA1: String = try getCertificateSHA1Hash(certificate: certificate).uppercased()
        logger.log("Using signing identity with SHA1: \(certificateSHA1)")

        // 8. --- Modify Info.plist (if requested) ---
        let infoPlistPath = appBundleUrl.appendingPathComponent("Info.plist").path
        if newBundleID != nil || newDisplayName != nil {
            logger.log("Modifying Info.plist...")
            try updateInfoPlist(path: infoPlistPath, newBundleID: newBundleID, newDisplayName: newDisplayName)
        } else {
            logger.log("No Info.plist modifications requested.", verboseOnly: true)
        }

        // 9. --- Prepare for Signing (Remove Old, Embed New Profile, Write Entitlements) ---
        logger.log("Removing existing code signature and profile (if present)...")
        let codeSignaturePath = appBundleUrl.appendingPathComponent("_CodeSignature").path
        let embeddedProfilePath = appBundleUrl.appendingPathComponent("embedded.mobileprovision").path
        try removeExistingSignature(codeSignaturePath: codeSignaturePath, embeddedProfilePath: embeddedProfilePath)

        logger.log("Embedding new provisioning profile...")
        try embedNewProvisioningProfile(sourcePath: provisioningProfilePath, targetPath: embeddedProfilePath)

        logger.log("Generating final entitlements file...")
        let entitlementsPath = tempDir.appendingPathComponent("entitlements.plist").path
        try writeEntitlements(finalEntitlements, to: entitlementsPath)

        // 10. --- Execute Code Signing (Recursive) ---
        logger.log("Signing component tree...")
        try signComponentTree(
            appBundleUrl: appBundleUrl,
            identitySHA1: certificateSHA1,
            entitlementsPath: entitlementsPath,
            signingOptions: options
        )

        // 11. --- Verify Signature ---
        logger.log("Verifying final signed application bundle...")
        try verifySignature(bundlePath: appBundleUrl.path)

        // 12. --- Re-zip IPA ---
        logger.log("Zipping signed application bundle into new IPA...")
        try zipOutputIpa(sourceDirectory: extractedIpaDir, outputPath: outputIpaPath)

        // 13. --- Completion ---
        logger.log("✅ Signing process completed successfully!")
        logger.log("Signed IPA saved to: \(URL(fileURLWithPath: outputIpaPath).relativePath)")
    }
}
