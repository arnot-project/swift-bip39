// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "arnot",
    products: [
        .library(
            name: "arnot",
            targets: ["arnot"]),
    ],
    targets: [
        .target(
            name: "arnot",
            dependencies: []),
        .testTarget(
            name: "arnotTests",
            dependencies: ["arnot"]),
    ]
)
