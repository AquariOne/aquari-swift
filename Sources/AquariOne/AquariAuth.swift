import Foundation

/// Provides OIDC discovery, Authorization Code with S256 PKCE, refresh-token rotation, and UserInfo
/// operations.
public actor AquariAuthClient {
  private let configuration: AquariResolvedConfiguration
  private let transport: AquariHTTPTransport
  private let jwtValidator: AquariJWTValidator
  private var cachedDiscovery: AquariOIDCDiscovery?

  init(
    configuration: AquariResolvedConfiguration, transport: AquariHTTPTransport,
    signatureVerifier: any AquariRS256SignatureVerifying = AquariDefaultRS256SignatureVerifier()
  ) {
    self.configuration = configuration
    self.transport = transport
    self.jwtValidator = AquariJWTValidator(
      transport: transport, signatureVerifier: signatureVerifier)
  }

  /// Loads and validates Aquari OpenID Connect discovery metadata. The client reuses cached metadata
  /// unless the caller requests a refresh.
  public func discover(forceRefresh: Bool = false) async throws -> AquariOIDCDiscovery {
    if !forceRefresh, let cachedDiscovery { return cachedDiscovery }
    let value = try await discoverOIDC(
      transport: transport, configuredIssuer: configuration.issuerString)
    cachedDiscovery = value
    return value
  }

  /// Starts an Authorization Code request. The SDK creates S256 PKCE, state, nonce, and a
  /// serializable authorization transaction, then returns the system-browser URL. Preserve the
  /// transaction until authorization completes.
  public func begin(prompt: AquariAuthorizationPrompt? = nil) async throws
    -> AquariBeginAuthorizationResult
  {
    let discovery = try await discover()
    let pkce = try AquariPKCE.create()
    let transaction = AquariAuthorizationTransaction(
      issuer: configuration.issuerString,
      clientID: configuration.clientID,
      redirectURI: configuration.redirectURIString,
      scopes: configuration.scopes,
      codeVerifier: pkce.codeVerifier,
      state: try secureRandomBase64URL(byteCount: 32),
      nonce: try secureRandomBase64URL(byteCount: 32),
      createdAt: Date()
    )
    guard
      var components = URLComponents(
        url: discovery.authorizationEndpoint, resolvingAgainstBaseURL: false)
    else {
      throw AquariError.configuration("Aquari authorization endpoint is invalid.")
    }
    var items = components.queryItems ?? []
    items += [
      URLQueryItem(name: "client_id", value: transaction.clientID),
      URLQueryItem(name: "redirect_uri", value: transaction.redirectURI),
      URLQueryItem(name: "response_type", value: "code"),
      URLQueryItem(name: "scope", value: transaction.scopes.joined(separator: " ")),
      URLQueryItem(name: "state", value: transaction.state),
      URLQueryItem(name: "nonce", value: transaction.nonce),
      URLQueryItem(name: "code_challenge", value: pkce.codeChallenge),
      URLQueryItem(name: "code_challenge_method", value: "S256"),
    ]
    if let prompt { items.append(URLQueryItem(name: "prompt", value: prompt.rawValue)) }
    components.queryItems = items
    guard let url = components.url else {
      throw AquariError.configuration("Aquari authorization URL could not be created.")
    }
    return AquariBeginAuthorizationResult(url: url, transaction: transaction)
  }

  /// Validates the authorization callback against the original transaction, exchanges the
  /// authorization code, validates the ID token and nonce, and returns subject-bound session state.
  public func complete(callbackURL: URL, transaction: AquariAuthorizationTransaction) async throws
    -> AquariAuthorizationResult
  {
    try validate(transaction: transaction)
    try validateCallbackURL(callbackURL, redirectURI: configuration.redirectURI)
    let parameters = try callbackParameters(callbackURL)
    guard parameters["state"] == transaction.state else {
      throw oauth(
        "state_mismatch",
        "Aquari authorization callback state does not match the initiating transaction.")
    }
    let callbackIssuer = parameters["iss"]
    if let callbackIssuer, callbackIssuer != transaction.issuer {
      throw oauth(
        "issuer_mismatch",
        "Aquari authorization callback issuer does not match the initiating transaction.")
    }

    let code = parameters["code"]
    let error = parameters["error"]
    if code != nil && error != nil {
      throw oauth(
        "invalid_callback",
        "Aquari authorization callback cannot contain both a code and an OAuth error.")
    }
    if let error {
      throw AquariError.oauth(
        AquariOAuthError(
          code: error,
          message: parameters["error_description"] ?? "Aquari returned OAuth error '\(error)'.",
          errorDescription: parameters["error_description"], errorURI: parameters["error_uri"]))
    }
    guard let code, !code.isEmpty else {
      throw oauth(
        "invalid_callback", "Aquari authorization callback does not contain an authorization code.")
    }
    let discovery = try await discover()
    if discovery.authorizationResponseIssuerParameterSupported && callbackIssuer == nil {
      throw oauth(
        "missing_issuer",
        "Aquari authorization callback is missing the advertised issuer parameter.")
    }
    return try await exchangeAuthorizationCode(
      code: code, transaction: transaction, discovery: discovery)
  }

  /// Exchanges the current refresh token for a replacement token set. Treat the returned token set as
  /// the new session state because Aquari rotates refresh tokens.
  public func refresh(_ tokens: AquariTokenSet) async throws -> AquariTokenSet {
    guard tokens.tokenType == "Bearer", !tokens.subject.isEmpty, !tokens.accessToken.isEmpty,
      !tokens.idToken.isEmpty, !tokens.scopes.isEmpty
    else { throw oauth("invalid_token_set", "Aquari refresh requires a valid SDK token set.") }
    guard let refreshToken = tokens.refreshToken, !refreshToken.isEmpty else {
      throw oauth(
        "missing_refresh_token",
        "Aquari cannot refresh this token set because it does not contain a refresh token.")
    }
    let discovery = try await discover()
    let body = formBody([
      "grant_type": "refresh_token", "client_id": configuration.clientID,
      "refresh_token": refreshToken,
    ])
    let (data, _) = try await transport.requestData(
      url: discovery.tokenEndpoint, method: .post,
      headers: ["Content-Type": "application/x-www-form-urlencoded"], body: body, retryMode: .never)
    let wire = try decodeJSON(
      RefreshTokenWire.self, from: data, context: "Aquari token refresh response")
    guard wire.tokenType.lowercased() == "bearer", wire.expiresIn > 0, !wire.accessToken.isEmpty
    else { throw oauth("invalid_token_response", "Aquari returned an invalid token response.") }
    let idToken = wire.idToken ?? tokens.idToken
    if idToken != tokens.idToken {
      let identity = try await jwtValidator.validate(
        idToken: idToken, discovery: discovery, clientID: configuration.clientID, expectedNonce: nil
      )
      guard identity.subject == tokens.subject else {
        throw oauth(
          "invalid_id_token",
          "Aquari refreshed ID token subject does not match the existing token set.")
      }
    }
    let scopes = try parseScope(wire.scope, fallback: tokens.scopes)
    return AquariTokenSet(
      subject: tokens.subject, tokenType: "Bearer", accessToken: wire.accessToken, idToken: idToken,
      refreshToken: wire.refreshToken ?? tokens.refreshToken, expiresIn: wire.expiresIn,
      expiresAt: Date().addingTimeInterval(wire.expiresIn), scopes: scopes)
  }

  /// Reads Aquari UserInfo with the current access token and returns the subject-bound identity.
  public func userInfo(_ tokens: AquariTokenSet) async throws -> AquariIdentity {
    let discovery = try await discover()
    let (data, _) = try await transport.requestData(
      url: discovery.userInfoEndpoint, headers: ["Authorization": "Bearer \(tokens.accessToken)"],
      retryMode: .never)
    guard let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw oauth("invalid_userinfo_response", "Aquari returned an invalid UserInfo response.")
    }
    let userIdentity: AquariIdentity
    do { userIdentity = try identity(from: payload) } catch {
      throw oauth("invalid_userinfo_response", "Aquari returned an invalid UserInfo response.")
    }
    guard userIdentity.subject == tokens.subject else {
      throw oauth(
        "userinfo_subject_mismatch",
        "Aquari UserInfo subject does not match the authenticated token set.")
    }
    return userIdentity
  }

  private func exchangeAuthorizationCode(
    code: String, transaction: AquariAuthorizationTransaction, discovery: AquariOIDCDiscovery
  ) async throws -> AquariAuthorizationResult {
    let body = formBody([
      "grant_type": "authorization_code", "client_id": transaction.clientID,
      "redirect_uri": transaction.redirectURI, "code": code,
      "code_verifier": transaction.codeVerifier,
    ])
    let (data, _) = try await transport.requestData(
      url: discovery.tokenEndpoint, method: .post,
      headers: ["Content-Type": "application/x-www-form-urlencoded"], body: body, retryMode: .never)
    let wire = try decodeJSON(
      AuthorizationTokenWire.self, from: data, context: "Aquari token exchange response")
    guard wire.tokenType.lowercased() == "bearer", wire.expiresIn > 0, !wire.accessToken.isEmpty,
      !wire.idToken.isEmpty
    else { throw oauth("invalid_token_response", "Aquari returned an invalid token response.") }
    let identity = try await jwtValidator.validate(
      idToken: wire.idToken, discovery: discovery, clientID: configuration.clientID,
      expectedNonce: transaction.nonce)
    let scopes = try parseScope(wire.scope, fallback: transaction.scopes)
    let tokens = AquariTokenSet(
      subject: identity.subject, tokenType: "Bearer", accessToken: wire.accessToken,
      idToken: wire.idToken, refreshToken: wire.refreshToken, expiresIn: wire.expiresIn,
      expiresAt: Date().addingTimeInterval(wire.expiresIn), scopes: scopes)
    return AquariAuthorizationResult(tokens: tokens, identity: identity)
  }

  private func validate(transaction: AquariAuthorizationTransaction) throws {
    let now = Date()
    guard transaction.version == 1,
      transaction.issuer == configuration.issuerString,
      transaction.clientID == configuration.clientID,
      transaction.redirectURI == configuration.redirectURIString,
      transaction.scopes == configuration.scopes,
      transaction.codeVerifier.count == 64, isBase64URL(transaction.codeVerifier),
      transaction.state.count == 43, isBase64URL(transaction.state),
      transaction.nonce.count == 43, isBase64URL(transaction.nonce)
    else {
      throw oauth(
        "invalid_transaction",
        "Aquari authorization transaction is invalid or does not match this client configuration.")
    }
    guard transaction.createdAt <= now.addingTimeInterval(60),
      now.timeIntervalSince(transaction.createdAt) <= 15 * 60
    else {
      throw oauth(
        "expired_transaction",
        "Aquari authorization transaction is expired or has an invalid timestamp.")
    }
  }
}

private struct AuthorizationTokenWire: Decodable, Sendable {
  let accessToken: String
  let idToken: String
  let refreshToken: String?
  let tokenType: String
  let expiresIn: TimeInterval
  let scope: String?
  enum CodingKeys: String, CodingKey {
    case accessToken = "access_token"
    case idToken = "id_token"
    case refreshToken = "refresh_token"
    case tokenType = "token_type"
    case expiresIn = "expires_in"
    case scope
  }
}
private struct RefreshTokenWire: Decodable, Sendable {
  let accessToken: String
  let idToken: String?
  let refreshToken: String?
  let tokenType: String
  let expiresIn: TimeInterval
  let scope: String?
  enum CodingKeys: String, CodingKey {
    case accessToken = "access_token"
    case idToken = "id_token"
    case refreshToken = "refresh_token"
    case tokenType = "token_type"
    case expiresIn = "expires_in"
    case scope
  }
}

private func formBody(_ fields: [String: String]) -> Data {
  var components = URLComponents()
  components.queryItems = fields.sorted(by: { $0.key < $1.key }).map {
    URLQueryItem(name: $0.key, value: $0.value)
  }
  return Data((components.percentEncodedQuery ?? "").utf8)
}
private func parseScope(_ value: String?, fallback: [String]) throws -> [String] {
  guard let value else { return fallback }
  let scopes = value.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
  guard !scopes.isEmpty, Set(scopes).count == scopes.count,
    scopes.allSatisfy({ !$0.isEmpty && !$0.contains(where: { $0.isWhitespace }) })
  else { throw oauth("invalid_token_response", "Aquari returned an invalid token response.") }
  return scopes
}
private func isBase64URL(_ value: String) -> Bool {
  value.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
}
private func oauth(_ code: String, _ message: String) -> AquariError {
  .oauth(AquariOAuthError(code: code, message: message))
}

private func validateCallbackURL(_ callback: URL, redirectURI: URL) throws {
  guard callback.fragment == nil,
    callback.scheme == redirectURI.scheme,
    callback.user == redirectURI.user,
    callback.password == redirectURI.password,
    callback.host == redirectURI.host,
    callback.port == redirectURI.port,
    callback.path == redirectURI.path
  else {
    throw oauth(
      "invalid_callback",
      "Aquari authorization callback URL does not match the configured redirect URI.")
  }
  let expected = URLComponents(url: redirectURI, resolvingAgainstBaseURL: false)?.queryItems ?? []
  let actual = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems ?? []
  for item in expected {
    guard actual.contains(where: { $0.name == item.name && $0.value == item.value }) else {
      throw oauth(
        "invalid_callback",
        "Aquari authorization callback URL does not match the configured redirect URI.")
    }
  }
}

private func callbackParameters(_ url: URL) throws -> [String: String] {
  let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
  var result: [String: String] = [:]
  for item in items
  where ["state", "iss", "error", "error_description", "error_uri", "code"].contains(item.name) {
    if result[item.name] != nil {
      throw oauth(
        "invalid_callback",
        "Aquari authorization callback contains multiple '\(item.name)' parameters.")
    }
    if let value = item.value, !value.isEmpty { result[item.name] = value }
  }
  return result
}
