// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AquariOne",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
    ],
    products: [
        .library(name: "AquariOne", targets: ["AquariOne"]),
    ],
    targets: [
        .target(name: "AquariOne"),
        .testTarget(name: "AquariOneTests", dependencies: ["AquariOne"]),
    ]
)
