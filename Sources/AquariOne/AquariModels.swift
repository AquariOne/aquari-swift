import Foundation

/// Lists the supported prompt values for an Aquari authorization request.
public enum AquariAuthorizationPrompt: String, Sendable, Codable {
  case consent
  case login
  case none
  case selectAccount = "select_account"
}

/// Stores the authorization transaction that binds an OAuth callback to the request that started
/// it. Preserve this value until authorization completes. Treat the PKCE verifier, state, and nonce
/// as sensitive.
public struct AquariAuthorizationTransaction: Sendable, Codable, Equatable {
  public let version: Int
  public let issuer: String
  public let clientID: String
  public let redirectURI: String
  public let scopes: [String]
  /// Gets the PKCE verifier. Treat this value as sensitive and preserve it only until callback
  /// completion.
  public let codeVerifier: String
  /// Gets the OAuth state value used to bind the callback to this transaction. Treat it as sensitive.
  public let state: String
  /// Gets the OpenID Connect nonce used to validate the returned ID token. Treat it as sensitive.
  public let nonce: String
  /// Gets the transaction creation time used to reject stale authorization state.
  public let createdAt: Date

  public init(
    version: Int = 1, issuer: String, clientID: String, redirectURI: String, scopes: [String],
    codeVerifier: String, state: String, nonce: String, createdAt: Date
  ) {
    self.version = version
    self.issuer = issuer
    self.clientID = clientID
    self.redirectURI = redirectURI
    self.scopes = scopes
    self.codeVerifier = codeVerifier
    self.state = state
    self.nonce = nonce
    self.createdAt = createdAt
  }
}

/// Contains the authorization URL and transaction created when an Aquari authorization request
/// starts.
public struct AquariBeginAuthorizationResult: Sendable, Equatable {
  public let url: URL
  public let transaction: AquariAuthorizationTransaction
}

/// Represents the subject-bound identity returned by Aquari UserInfo.
public struct AquariIdentity: Sendable, Codable, Equatable {
  public let subject: String
  public let handle: String?
  public let canonicalHandle: String?
  public let verifiedHandle: String?
  public let name: String?
  public let pictureURL: String?
  public let email: String?
  public let emailVerified: Bool?
}

/// Contains the OAuth tokens, subject, scopes, and expiration metadata for an Aquari session. Do
/// not log or expose token values.
public struct AquariTokenSet: Sendable, Codable, Equatable {
  /// Gets the stable Aquari subject identifier bound to this token set.
  public let subject: String
  public let tokenType: String
  /// Gets the bearer access token. Do not log or expose this value.
  public let accessToken: String
  /// Gets the validated OpenID Connect ID token. Do not log or expose this value.
  public let idToken: String
  /// Gets the current refresh token when one is available. Aquari can rotate this value; always
  /// persist the replacement token set.
  public let refreshToken: String?
  public let expiresIn: TimeInterval
  /// Gets the time when the access token expires.
  public let expiresAt: Date
  public let scopes: [String]
}

/// Contains the validated token set and subject-bound Aquari identity produced by authorization.
public struct AquariAuthorizationResult: Sendable, Equatable {
  public let tokens: AquariTokenSet
  public let identity: AquariIdentity
}
