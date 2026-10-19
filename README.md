# AquariOne Swift SDK

Native Aquari One SDK for Apple applications.

## Capabilities

- Swift Package Manager library product `AquariOne`;
- Swift 6 concurrency-safe API surface;
- Authorization Code with S256 PKCE;
- OpenID Connect discovery, callback validation, RS256/JWKS ID-token validation, refresh-token rotation, and UserInfo;
- connected Passport, Passport signals, public Passport, and trust reads;
- `ASWebAuthenticationSession` authorization through `AquariAppleClient`;
- Keychain-backed authorization-transaction and token storage;
- restart-safe session restore, explicit refresh, and local sign-out.

## Requirements

- Swift 6 toolchain
- iOS 15+
- macOS 13+ for development and testing

## Security boundary

Apple applications are public OAuth clients. Do not embed a confidential client secret, machine API key, or privileged issuer credential.

The default Keychain accessibility is `afterFirstUnlockThisDeviceOnly`. A custom Keychain access group can be supplied when an application intentionally shares Aquari credentials across its own signed targets.

Aquari authenticates the person and exposes portable Passport and trust data. The consuming application decides its own local roles and permissions.

## Documentation

See `https://docs.aquari.one/sdks/swift` for the integration guide and API reference.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

Source repository (GitLab, authoritative): https://gitlab.com/nousen-group/aquari/aquari-swift
GitHub read-only mirror: https://github.com/AquariOne/aquari-swift

The public SDK source is exported from Aquari One’s private monorepo. Contributions and release decisions are managed on GitLab; do not push directly to the GitHub mirror.
