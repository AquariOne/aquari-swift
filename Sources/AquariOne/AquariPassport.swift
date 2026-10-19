import Foundation

/// Identifies the Aquari signal family represented by a Passport signal.
public enum AquariPassportSignalFamily: String, Sendable, Codable {
  case badge, stamp, credential, entitlement, role, membership, unknown
}
/// Contains the profile fields exposed by a connected Aquari Passport.
public struct AquariPassportProfile: Sendable, Equatable {
  public let displayName: String
  public let handle: String
  public let avatarURL: String?
  public let publicURL: String
  public let verified: Bool
  public let visibility: String
}
/// Contains the total number of signals reported for a connected Passport.
public struct AquariPassportSignalSummary: Sendable, Equatable { public let total: Int }
/// Represents the connected Passport returned for the authenticated Aquari subject.
public struct AquariPassport: Sendable, Equatable {
  public let id: String
  public let passportNumber: String
  public let subjectID: String
  public let profile: AquariPassportProfile
  public let signals: AquariPassportSignalSummary
}
/// Identifies the issuer that produced a Passport signal.
public struct AquariPassportSignalIssuer: Sendable, Equatable {
  public let type: String
  public let id: String
  public let name: String
  public let logoURL: String?
}
/// Identifies the resource scope attached to a Passport signal.
public struct AquariPassportSignalScope: Sendable, Equatable {
  public let type: String
  public let id: String
}
/// Represents one portable signal on an Aquari Passport.
public struct AquariPassportSignal: Sendable, Equatable {
  public let id: String
  public let subjectID: String
  public let family: AquariPassportSignalFamily
  public let sourceType: String
  public let definitionID: String?
  public let presentationType: String
  public let name: String
  public let description: String
  public let imageURL: String?
  public let issuer: AquariPassportSignalIssuer
  public let issuedAt: String
  public let expiresAt: String?
  public let visibility: String
  public let verified: Bool
  public let occurredAt: String?
  public let scope: AquariPassportSignalScope?
}
/// Contains one page of Passport signals and cursor pagination state.
public struct AquariPassportSignalPage: Sendable, Equatable {
  public let items: [AquariPassportSignal]
  public let nextCursor: String?
  public let hasMore: Bool
}
/// Represents one signal that is visible on a public Aquari Passport.
public struct AquariPublicPassportSignal: Sendable, Equatable {
  public let id: String
  public let type: String
  public let name: String
  public let description: String
  public let imageURL: String?
  public let issuer: String
  public let issuerLogoURL: String?
  public let issuedAt: String
  public let expiresAt: String?
  public let verified: Bool
  public let occurredAt: String?
  public let scope: AquariPassportSignalScope?
}
/// Represents public Passport data that can be read by handle without an authenticated session.
public struct AquariPublicPassport: Sendable, Equatable {
  public let displayName: String
  public let handle: String
  public let avatarURL: String?
  public let publicURL: String
  public let verified: Bool
  public let signals: [AquariPublicPassportSignal]
}
/// Configures Passport signal filtering and cursor pagination.
public struct AquariPassportSignalFilters: Sendable, Equatable {
  public var type: String?
  public var issuerID: String?
  public var definitionID: String?
  public var limit: Int?
  public var cursor: String?
  public init(
    type: String? = nil, issuerID: String? = nil, definitionID: String? = nil, limit: Int? = nil,
    cursor: String? = nil
  ) {
    self.type = type
    self.issuerID = issuerID
    self.definitionID = definitionID
    self.limit = limit
    self.cursor = cursor
  }
}

private struct PassportEnvelope: Decodable, Sendable { let passport: PassportWire }
private struct SignalEnvelope: Decodable, Sendable { let signal: SignalWire }
private struct PassportWire: Decodable, Sendable {
  let id: String
  let passportNumber: String
  let subjectId: String
  let profile: ProfileWire
  let signals: SummaryWire
}
private struct ProfileWire: Decodable, Sendable {
  let displayName: String
  let handle: String
  let avatarUrl: String?
  let publicUrl: String
  let verified: Bool
  let visibility: String
}
private struct SummaryWire: Decodable, Sendable { let total: Int }
private struct SignalPageWire: Decodable, Sendable {
  let items: [SignalWire]
  let page: PageWire
}
private struct PageWire: Decodable, Sendable {
  let nextCursor: String?
  let hasMore: Bool
}
private struct IssuerWire: Decodable, Sendable {
  let type: String
  let id: String
  let name: String
  let logoUrl: String?
}
private struct ScopeWire: Decodable, Sendable {
  let type: String
  let id: String
}
private struct SignalWire: Decodable, Sendable {
  let id: String
  let subjectId: String
  let sourceType: String
  let definitionId: String?
  let type: String
  let name: String
  let description: String
  let imageUrl: String?
  let issuer: IssuerWire
  let issuedAt: String
  let expiresAt: String?
  let visibility: String
  let verified: Bool
  let occurredAt: String?
  let scope: ScopeWire?
}
private struct PublicPassportWire: Decodable, Sendable {
  let displayName: String
  let handle: String
  let avatarUrl: String?
  let publicUrl: String
  let verified: Bool
  let signals: [PublicSignalWire]
}
private struct PublicSignalWire: Decodable, Sendable {
  let id: String
  let type: String
  let name: String
  let description: String
  let imageUrl: String?
  let issuer: String
  let issuerLogoUrl: String?
  let issuedAt: String
  let expiresAt: String?
  let verified: Bool
  let occurredAt: String?
  let scope: ScopeWire?
}

/// Lists and reads signals on the authenticated subject's Passport.
public struct AquariPassportSignalsClient: Sendable {
  let transport: AquariHTTPTransport
  /// Reads one page of Passport signals using the supplied filters and cursor.
  public func list(accessToken: String, filters: AquariPassportSignalFilters = .init()) async throws
    -> AquariPassportSignalPage
  {
    if let limit = filters.limit, !(1...100).contains(limit) {
      throw AquariError.configuration(
        "Aquari Passport signal limit must be an integer from 1 through 100.")
    }
    var components = URLComponents()
    var items: [URLQueryItem] = []
    if let value = filters.type {
      items.append(URLQueryItem(name: "type", value: try requireNonEmpty(value, field: "type")))
    }
    if let value = filters.issuerID {
      items.append(
        URLQueryItem(name: "issuer_id", value: try requireNonEmpty(value, field: "issuerID")))
    }
    if let value = filters.definitionID {
      items.append(
        URLQueryItem(
          name: "definition_id", value: try requireNonEmpty(value, field: "definitionID")))
    }
    if let value = filters.limit { items.append(URLQueryItem(name: "limit", value: String(value))) }
    if let value = filters.cursor {
      items.append(URLQueryItem(name: "cursor", value: try requireNonEmpty(value, field: "cursor")))
    }
    components.queryItems = items
    let path =
      items.isEmpty
      ? "/api/v1/passport/signals"
      : "/api/v1/passport/signals?\(components.percentEncodedQuery ?? "")"
    let wire = try await transport.requestJSON(
      SignalPageWire.self, path: path, headers: try bearerHeaders(accessToken))
    return AquariPassportSignalPage(
      items: try wire.items.map(parseSignal), nextCursor: wire.page.nextCursor,
      hasMore: wire.page.hasMore)
  }
  /// Reads one Passport signal by identifier for the authenticated subject.
  public func get(_ signalID: String, accessToken: String) async throws -> AquariPassportSignal {
    let id = try encodePathSegment(signalID, label: "signalID")
    let wire = try await transport.requestJSON(
      SignalEnvelope.self, path: "/api/v1/passport/signals/\(id)",
      headers: try bearerHeaders(accessToken))
    return try parseSignal(wire.signal)
  }
  /// Streams Passport signals across cursor pages until Aquari reports that no additional page is
  /// available.
  public func iterate(accessToken: String, filters: AquariPassportSignalFilters = .init())
    -> AsyncThrowingStream<AquariPassportSignal, Error>
  {
    AsyncThrowingStream { continuation in
      let task = Task {
        do {
          var current = filters
          while true {
            let page = try await list(accessToken: accessToken, filters: current)
            for item in page.items { continuation.yield(item) }
            guard page.hasMore, let cursor = page.nextCursor else { break }
            current.cursor = cursor
          }
          continuation.finish()
        } catch { continuation.finish(throwing: error) }
      }
      continuation.onTermination = { _ in task.cancel() }
    }
  }
}

/// Reads connected and public Passport data.
public struct AquariPassportClient: Sendable {
  let transport: AquariHTTPTransport
  /// Gets Passport signal read operations.
  public let signals: AquariPassportSignalsClient
  init(transport: AquariHTTPTransport) {
    self.transport = transport
    self.signals = AquariPassportSignalsClient(transport: transport)
  }
  /// Reads the connected Passport for the authenticated subject represented by the supplied access
  /// token.
  public func get(accessToken: String) async throws -> AquariPassport {
    let wire = try await transport.requestJSON(
      PassportEnvelope.self, path: "/api/v1/passport", headers: try bearerHeaders(accessToken))
    return try parsePassport(wire.passport)
  }
  /// Reads public Passport data for the supplied Aquari handle without using a bearer access token.
  public func getPublic(handle: String) async throws -> AquariPublicPassport {
    let encoded = try encodePathSegment(handle, label: "handle")
    let wire = try await transport.requestJSON(
      PublicPassportWire.self, path: "/api/v1/public/passports/\(encoded)")
    return try parsePublicPassport(wire)
  }
}

private func parsePassport(_ w: PassportWire) throws -> AquariPassport {
  AquariPassport(
    id: try requireNonEmpty(w.id, field: "Passport id"),
    passportNumber: try requireNonEmpty(w.passportNumber, field: "Passport number"),
    subjectID: try requireNonEmpty(w.subjectId, field: "Passport subject id"),
    profile: AquariPassportProfile(
      displayName: w.profile.displayName,
      handle: try requireNonEmpty(w.profile.handle, field: "Passport handle"),
      avatarURL: w.profile.avatarUrl,
      publicURL: try requireNonEmpty(w.profile.publicUrl, field: "Passport public URL"),
      verified: w.profile.verified,
      visibility: try requireNonEmpty(w.profile.visibility, field: "Passport visibility")),
    signals: AquariPassportSignalSummary(total: w.signals.total))
}
private func parseSignal(_ w: SignalWire) throws -> AquariPassportSignal {
  AquariPassportSignal(
    id: try requireNonEmpty(w.id, field: "signal id"),
    subjectID: try requireNonEmpty(w.subjectId, field: "signal subject id"),
    family: family(w.sourceType, w.type),
    sourceType: try requireNonEmpty(w.sourceType, field: "signal sourceType"),
    definitionID: w.definitionId,
    presentationType: try requireNonEmpty(w.type, field: "signal type"),
    name: try requireNonEmpty(w.name, field: "signal name"), description: w.description,
    imageURL: w.imageUrl,
    issuer: AquariPassportSignalIssuer(
      type: try requireNonEmpty(w.issuer.type, field: "issuer type"),
      id: try requireNonEmpty(w.issuer.id, field: "issuer id"),
      name: try requireNonEmpty(w.issuer.name, field: "issuer name"), logoURL: w.issuer.logoUrl),
    issuedAt: try requireISO8601(w.issuedAt, field: "issuedAt"),
    expiresAt: try w.expiresAt.map { try requireISO8601($0, field: "expiresAt") },
    visibility: try requireNonEmpty(w.visibility, field: "visibility"), verified: w.verified,
    occurredAt: try w.occurredAt.map { try requireISO8601($0, field: "occurredAt") },
    scope: try w.scope.map {
      AquariPassportSignalScope(
        type: try requireNonEmpty($0.type, field: "scope type"),
        id: try requireNonEmpty($0.id, field: "scope id"))
    })
}
private func parsePublicPassport(_ w: PublicPassportWire) throws -> AquariPublicPassport {
  AquariPublicPassport(
    displayName: w.displayName,
    handle: try requireNonEmpty(w.handle, field: "public Passport handle"), avatarURL: w.avatarUrl,
    publicURL: try requireNonEmpty(w.publicUrl, field: "public Passport URL"), verified: w.verified,
    signals: try w.signals.map { try parsePublicSignal($0) })
}
private func parsePublicSignal(_ w: PublicSignalWire) throws -> AquariPublicPassportSignal {
  AquariPublicPassportSignal(
    id: try requireNonEmpty(w.id, field: "public signal id"),
    type: try requireNonEmpty(w.type, field: "public signal type"),
    name: try requireNonEmpty(w.name, field: "public signal name"), description: w.description,
    imageURL: w.imageUrl, issuer: try requireNonEmpty(w.issuer, field: "public signal issuer"),
    issuerLogoURL: w.issuerLogoUrl, issuedAt: try requireISO8601(w.issuedAt, field: "issuedAt"),
    expiresAt: try w.expiresAt.map { try requireISO8601($0, field: "expiresAt") },
    verified: w.verified,
    occurredAt: try w.occurredAt.map { try requireISO8601($0, field: "occurredAt") },
    scope: try w.scope.map {
      AquariPassportSignalScope(
        type: try requireNonEmpty($0.type, field: "scope type"),
        id: try requireNonEmpty($0.id, field: "scope id"))
    })
}
private func family(_ source: String, _ type: String) -> AquariPassportSignalFamily {
  if source == "badge" && type == "badge" { return .badge }
  if source == "passport_stamp" && type == "stamp" { return .stamp }
  if source == "credential" && type == "credential" { return .credential }
  if source == "user_entitlement" && type == "credential" { return .entitlement }
  if source == "app_membership" && type == "role" { return .role }
  if source == "app_membership" && type == "membership" { return .membership }
  return .unknown
}
