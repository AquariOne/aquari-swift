import Foundation

/// Reports an OAuth or OpenID Connect protocol failure.
public struct AquariOAuthError: Error, Sendable, Equatable {
  public let code: String
  public let message: String
  public let errorDescription: String?
  public let errorURI: String?

  /// Creates an OAuth or OpenID Connect protocol error and preserves the protocol error code and
  /// optional metadata.
  public init(
    code: String, message: String, errorDescription: String? = nil, errorURI: String? = nil
  ) {
    self.code = code
    self.message = message
    self.errorDescription = errorDescription
    self.errorURI = errorURI
  }
}

/// Classifies structured Aquari API errors by response category.
public enum AquariAPIErrorKind: String, Sendable, Equatable {
  case generic
  case validation
  case authentication
  case authorization
  case notFound
  case conflict
  case rateLimit
  case quota
}

/// Contains quota limits and usage metadata returned with an Aquari quota error.
public struct AquariQuotaMetadata: Sendable, Equatable {
  public let resource: String?
  public let scopeType: String?
  public let scopeID: String?
  public let current: Double?
  public let requested: Double?
  public let limit: Double?
  public let allowance: Double?
  public let grace: Double?
  public let periodFrom: Date?
  public let periodTo: Date?
  public let enforcement: String?
}

/// Reports a structured non-success response returned by an Aquari API endpoint.
public struct AquariAPIError: Error, Sendable, Equatable {
  public let kind: AquariAPIErrorKind
  public let status: Int
  public let code: String?
  public let message: String
  public let details: [String: [String]]?
  /// Gets the server-provided retry delay when Aquari supplied one.
  public let retryAfter: TimeInterval?
  public let quota: AquariQuotaMetadata?

  public init(
    kind: AquariAPIErrorKind,
    status: Int,
    code: String?,
    message: String,
    details: [String: [String]]? = nil,
    retryAfter: TimeInterval? = nil,
    quota: AquariQuotaMetadata? = nil
  ) {
    self.kind = kind
    self.status = status
    self.code = code
    self.message = message
    self.details = details
    self.retryAfter = retryAfter
    self.quota = quota
  }
}

/// Classifies configuration, transport, timeout, API, and OAuth failures produced by the Swift SDK.
public enum AquariError: Error, Sendable, Equatable {
  case configuration(String)
  case transport(String)
  case cancelled
  case timeout(TimeInterval)
  case invalidResponse(String)
  case secureStorage(String)
  case api(AquariAPIError)
  case oauth(AquariOAuthError)
  case platformUnsupported(String)
}
