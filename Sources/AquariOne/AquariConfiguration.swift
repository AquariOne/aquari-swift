import Foundation

/// Configures an Aquari OAuth client and its HTTP behavior. Do not put a confidential client secret
/// in distributable client code.
public struct AquariClientOptions: Sendable {
  /// Sets the absolute Aquari issuer URL. Remote issuers must use HTTPS.
  public var issuer: URL
  public var clientID: String
  public var redirectURI: URL
  /// Sets the OAuth scopes requested during authorization. Request offline_access when the
  /// application needs refresh tokens.
  public var scopes: [String]
  public var requestTimeout: TimeInterval
  /// Sets the maximum number of transport retries after the first request attempt.
  public var maxRetries: Int
  public var maxRetryDelay: TimeInterval
  public var httpClient: (any AquariHTTPClient)?

  public init(
    issuer: URL,
    clientID: String,
    redirectURI: URL,
    scopes: [String],
    requestTimeout: TimeInterval = 15,
    maxRetries: Int = 2,
    maxRetryDelay: TimeInterval = 5,
    httpClient: (any AquariHTTPClient)? = nil
  ) {
    self.issuer = issuer
    self.clientID = clientID
    self.redirectURI = redirectURI
    self.scopes = scopes
    self.requestTimeout = requestTimeout
    self.maxRetries = maxRetries
    self.maxRetryDelay = maxRetryDelay
    self.httpClient = httpClient
  }
}

struct AquariResolvedConfiguration: Sendable {
  let issuer: URL
  let issuerString: String
  let clientID: String
  let redirectURI: URL
  let redirectURIString: String
  let scopes: [String]
  let requestTimeout: TimeInterval
  let maxRetries: Int
  let maxRetryDelay: TimeInterval
}

func resolveConfiguration(_ options: AquariClientOptions) throws -> AquariResolvedConfiguration {
  let issuer = try normalizeAquariBaseURL(options.issuer)
  let clientID = options.clientID
  guard !clientID.isEmpty, clientID == clientID.trimmingCharacters(in: .whitespacesAndNewlines),
    !clientID.contains(where: { $0.isWhitespace })
  else {
    throw AquariError.configuration("Aquari clientID must be a non-empty value without whitespace.")
  }

  let redirect = try validateRedirectURI(options.redirectURI)
  let scopes = try validateScopes(options.scopes)

  guard options.requestTimeout.isFinite, options.requestTimeout > 0 else {
    throw AquariError.configuration("requestTimeout must be positive.")
  }
  guard options.maxRetries >= 0 else {
    throw AquariError.configuration("maxRetries must be non-negative.")
  }
  guard options.maxRetryDelay.isFinite, options.maxRetryDelay >= 0 else {
    throw AquariError.configuration("maxRetryDelay must be non-negative.")
  }

  return AquariResolvedConfiguration(
    issuer: issuer,
    issuerString: issuer.absoluteString,
    clientID: clientID,
    redirectURI: redirect,
    redirectURIString: redirect.absoluteString,
    scopes: scopes,
    requestTimeout: options.requestTimeout,
    maxRetries: options.maxRetries,
    maxRetryDelay: options.maxRetryDelay
  )
}

/// Validates and normalizes the supplied Aquari base URL without changing its identity.
public func normalizeAquariBaseURL(_ value: URL) throws -> URL {
  guard var components = URLComponents(url: value, resolvingAgainstBaseURL: false),
    let scheme = components.scheme?.lowercased(),
    scheme == "https" || scheme == "http",
    components.host != nil
  else {
    throw AquariError.configuration("Aquari base URL must be a valid absolute HTTP(S) URL.")
  }

  if scheme == "http", !isLocalDevelopmentHost(components.host ?? "") {
    throw AquariError.configuration(
      "Insecure HTTP Aquari URLs are allowed only for local development.")
  }
  guard components.user == nil, components.password == nil else {
    throw AquariError.configuration("Aquari base URL must not contain credentials.")
  }
  guard components.query == nil, components.fragment == nil else {
    throw AquariError.configuration("Aquari base URL must not contain a query string or fragment.")
  }
  if !components.path.hasSuffix("/") {
    components.path += "/"
  }
  guard let url = components.url else {
    throw AquariError.configuration("Aquari base URL could not be normalized.")
  }
  return url
}

func validateRedirectURI(_ value: URL) throws -> URL {
  guard let components = URLComponents(url: value, resolvingAgainstBaseURL: false),
    components.scheme != nil
  else {
    throw AquariError.configuration("Aquari redirectURI must be a valid absolute URI.")
  }
  guard components.user == nil, components.password == nil else {
    throw AquariError.configuration("Aquari redirectURI must not contain credentials.")
  }
  guard components.fragment == nil else {
    throw AquariError.configuration("Aquari redirectURI must not contain a fragment.")
  }
  return value
}

func validateScopes(_ values: [String]) throws -> [String] {
  guard !values.isEmpty else {
    throw AquariError.configuration("Aquari scopes must contain at least one explicit scope.")
  }
  var seen = Set<String>()
  for scope in values {
    guard !scope.isEmpty,
      scope == scope.trimmingCharacters(in: .whitespacesAndNewlines),
      !scope.contains(where: { $0.isWhitespace })
    else {
      throw AquariError.configuration(
        "Aquari scope values must be non-empty and must not contain whitespace.")
    }
    guard seen.insert(scope).inserted else {
      throw AquariError.configuration("Aquari scope values must not contain duplicates.")
    }
  }
  guard seen.contains(AquariScopes.openID) else {
    throw AquariError.configuration("Aquari authentication requires the explicit 'openid' scope.")
  }
  return values
}

func isLocalDevelopmentHost(_ host: String) -> Bool {
  let normalized = host.lowercased()
  return normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1"
    || normalized == "[::1]"
}
