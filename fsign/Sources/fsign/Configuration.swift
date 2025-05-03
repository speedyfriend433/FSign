//
//  File.swift
//  FSign
//
//  Created by 이지안 on 5/3/25.
//

import Foundation

/// Options controlling the code signing process.
public struct SigningOptions {
    /// Whether to include a secure timestamp with the signature (requires network). Defaults to `true`.
    public var useTimestamp: Bool
    /// Whether to enable the hardened runtime for the signed code. Defaults to `true`.
    public var useHardenedRuntime: Bool
    /// The cryptographic digest algorithm to use (e.g., "sha1", "sha256"). Defaults to "sha256".
    public var digestAlgorithm: String
    // Potential future options:
    // public var keychainPath: String? = nil // Path to specific keychain
    // public var customCodesignFlags: [String] = [] // Inject arbitrary flags

    /// Initializes new signing options.
    /// - Parameters:
    ///   - useTimestamp: Include a secure timestamp. Defaults to `true`.
    ///   - useHardenedRuntime: Enable the hardened runtime. Defaults to `true`.
    ///   - digestAlgorithm: Digest algorithm ("sha1" or "sha256"). Defaults to "sha256".
    public init(
        useTimestamp: Bool = true,
        useHardenedRuntime: Bool = true,
        digestAlgorithm: String = "sha256"
    ) {
        self.useTimestamp = useTimestamp
        self.useHardenedRuntime = useHardenedRuntime
        self.digestAlgorithm = digestAlgorithm
    }
}

/// A closure type that takes a dictionary of base entitlements (extracted from the profile)
/// and returns a potentially modified dictionary of entitlements to be embedded.
/// Can throw an error if processing fails.
public typealias EntitlementProcessor = ([String: Any]) throws -> [String: Any]
