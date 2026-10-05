// swift-tools-version: 5.7

import PackageDescription

// The local ChioKernel xcframework is produced by
// `scripts/build-ios-framework.sh` and committed under Frameworks/.

let package = Package(
    name: "Chio",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "Chio",
            targets: ["Chio"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "ChioKernel",
            path: "Frameworks/ChioKernel.xcframework"
        ),
        .target(
            name: "chio_kernel_mobile",
            dependencies: ["ChioKernel"],
            path: "Sources/chio_kernel_mobile"
        ),
        .target(
            name: "Chio",
            dependencies: [
                "chio_kernel_mobile"
            ]
        ),
        .testTarget(
            name: "ChioTests",
            dependencies: ["Chio"]
        )
    ]
)
