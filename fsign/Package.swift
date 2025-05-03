// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.
// swift-tools-version:5.7 // Or your preferred version
// swift-tools-version:5.7 // Or your version
import PackageDescription

let package = Package(
    name: "FSign",
    platforms: [
        .macOS(.v11) // Ensure this platform is specified
    ],
    products: [
        .library(
            name: "FSign",
            targets: ["FSign"]),
    ],
    dependencies: [
        .package(url: "https://github.com/weichsel/ZIPFoundation.git", .upToNextMajor(from: "0.9.0"))
    ],
    targets: [
        .target(
            name: "FSign",
            dependencies: ["ZIPFoundation"],
            linkerSettings: [
                // --- Add or verify this line ---
                .linkedFramework("Security")
                // ---------------------------------
            ]
            ),
        .testTarget(
            name: "FSignTests",
            dependencies: ["FSign"]),
    ]
)
