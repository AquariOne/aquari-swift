import Foundation

/// Provides the main Aquari runtime entry point for authentication, Passport, and trust operations.
public struct AquariClient: Sendable {
  /// Gets the normalized Aquari issuer URL.
  public let issuer: URL
  /// Gets the configured OAuth client identifier.
  public let clientID: String
  /// Gets the registered OAuth redirect URI.
  public let redirectURI: URL
  /// Gets the OAuth scopes requested by this client.
  public let scopes: [String]
  /// Gets authentication and token-lifecycle operations.
  public let auth: AquariAuthClient
  /// Gets Passport read operations.
  public let passport: AquariPassportClient
  /// Gets trust-evaluation operations.
  public let trust: AquariTrustClient

  /// Creates the main Aquari client from validated OAuth and HTTP configuration.
  public init(options: AquariClientOptions) throws {
    let configuration = try resolveConfiguration(options)
    let transport = AquariHTTPTransport(
      baseURL: configuration.issuer, timeout: configuration.requestTimeout,
      maxRetries: configuration.maxRetries, maxRetryDelay: configuration.maxRetryDelay,
      client: options.httpClient ?? AquariURLSessionHTTPClient())
    self.issuer = configuration.issuer
    self.clientID = configuration.clientID
    self.redirectURI = configuration.redirectURI
    self.scopes = configuration.scopes
    self.auth = AquariAuthClient(configuration: configuration, transport: transport)
    self.passport = AquariPassportClient(transport: transport)
    self.trust = AquariTrustClient(transport: transport)
  }

  init(options: AquariClientOptions, signatureVerifier: any AquariRS256SignatureVerifying) throws {
    let configuration = try resolveConfiguration(options)
    let transport = AquariHTTPTransport(
      baseURL: configuration.issuer, timeout: configuration.requestTimeout,
      maxRetries: configuration.maxRetries, maxRetryDelay: configuration.maxRetryDelay,
      client: options.httpClient ?? AquariURLSessionHTTPClient())
    self.issuer = configuration.issuer
    self.clientID = configuration.clientID
    self.redirectURI = configuration.redirectURI
    self.scopes = configuration.scopes
    self.auth = AquariAuthClient(
      configuration: configuration, transport: transport, signatureVerifier: signatureVerifier)
    self.passport = AquariPassportClient(transport: transport)
    self.trust = AquariTrustClient(transport: transport)
  }
}
