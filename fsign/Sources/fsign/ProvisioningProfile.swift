//
//  File.swift
//  FSign
//
//  Created by 이지안 on 5/3/25.
//

import Foundation
import Security

extension FSigner {

    // MARK: - Provisioning Profile Handling

    internal func parseProvisioningProfile(path: String) throws -> [String: Any] {
        let profileData: Data
        do {
            profileData = try Data(contentsOf: URL(fileURLWithPath: path))
        } catch {
            throw FSignError.provisioningProfileParsingFailed(reason: "Could not read file data: \(error.localizedDescription)")
        }

        var decoder: SecCMSDecoder? 
        guard SecCMSDecoderCreate(&decoder) == errSecSuccess else {
            throw FSignError.cmsDecoderCreationFailed
        }
        guard let cmsDecoder = decoder else {
             throw FSignError.cmsDecoderCreationFailed
        }

        let statusUpdate = profileData.withUnsafeBytes { (rawBufferPointer: UnsafeRawBufferPointer) -> OSStatus in
            guard let baseAddress = rawBufferPointer.baseAddress else { return errSecParam }
            return SecCMSDecoderUpdateMessage(cmsDecoder, baseAddress, rawBufferPointer.count)
        }
        guard statusUpdate == errSecSuccess else {
             throw FSignError.cmsUpdateFailed
        }

        guard SecCMSDecoderFinalizeMessage(cmsDecoder) == errSecSuccess else {
             throw FSignError.cmsFinalizeFailed
        }

        var extractedDataCF: CFData?
        guard SecCMSDecoderCopyContent(cmsDecoder, &extractedDataCF) == errSecSuccess else {
            throw FSignError.cmsContentExtractionFailed
        }

        guard let extractedData = extractedDataCF as Data? else {
             throw FSignError.cmsContentExtractionFailed
        }

        do {
            let plist = try PropertyListSerialization.propertyList(from: extractedData, options: [], format: nil)
            guard let dict = plist as? [String: Any] else {
                throw FSignError.invalidProvisioningProfileFormat("Root object is not a dictionary.")
            }
            logger.log("Successfully parsed provisioning profile.", verboseOnly: true)
            return dict
        } catch {
            throw FSignError.provisioningProfileParsingFailed(reason: "Failed to deserialize plist: \(error.localizedDescription)")
        }
    }

    internal func extractEntitlements(from profileInfo: [String: Any]) throws -> [String: Any] {
         guard let entitlements = profileInfo["Entitlements"] as? [String: Any] else {
             throw FSignError.invalidProvisioningProfileFormat("Missing or invalid 'Entitlements' dictionary in profile.")
         }
         logger.log("Successfully extracted entitlements from profile.", verboseOnly: true)
         return entitlements
    }
}
