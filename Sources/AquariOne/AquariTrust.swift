import Foundation

/// Identifies the authority attached to a trusted signal.
public struct AquariTrustAuthority: Sendable, Equatable {
  public let type: String
  public let id: String
}

/// Identifies the resource scope attached to a trusted signal.
public struct AquariTrustScope: Sendable, Equatable {
  public let type: String
  public let id: String
}

/// Describes the Passport signal that supported a trust outcome.
public struct AquariTrustSignal: Sendable, Equatable {
  public let id: String
  public let signalFamily: String
  public let definitionID: String?
  public let authority: AquariTrustAuthority
  public let scope: AquariTrustScope?
  public let issuedAt: String
  public let expiresAt: String?
}

/// Explains which trusted mapping and signal support a trust outcome.
public struct AquariTrustSupport: Sendable, Equatable {
  public let mappingID: String
  public let mappingVersion: Int
  public let trustedIssuerID: String
  public let signal: AquariTrustSignal
}

/// Represents one trust outcome and the signals that support it.
public struct AquariTrustOutcome: Sendable, Equatable {
  public let type: String
  public let value: String
  public let supports: [AquariTrustSupport]
}

/// Contains the trust outcomes Aquari calculated for one subject and consumer application.
public struct AquariTrustEvaluation: Sendable, Equatable {
  public let evaluationID: String
  public let subjectID: String
  public let consumerApplicationID: String
  public let evaluatedAt: String
  public let outcomes: [AquariTrustOutcome]
}

private struct EvaluationWire: Decodable, Sendable {
  let evaluationId: String
  let subjectId: String
  let consumerApplicationId: String
  let evaluatedAt: String
  let outcomes: [OutcomeWire]
}

private struct OutcomeWire: Decodable, Sendable {
  let type: String
  let value: String
  let supports: [SupportWire]
}

private struct SupportWire: Decodable, Sendable {
  let mappingId: String
  let mappingVersion: Int
  let trustedIssuerId: String
  let signal: TrustSignalWire
}

private struct TrustSignalWire: Decodable, Sendable {
  let id: String
  let signalFamily: String
  let definitionId: String?
  let authority: AuthorityWire
  let scope: TrustScopeWire?
  let issuedAt: String
  let expiresAt: String?
}

private struct AuthorityWire: Decodable, Sendable {
  let type: String
  let id: String
}

private struct TrustScopeWire: Decodable, Sendable {
  let type: String
  let id: String
}

/// Evaluates the current application's configured trust mappings for an authenticated Aquari
/// subject.
public struct AquariTrustClient: Sendable {
  let transport: AquariHTTPTransport

  /// Requests Aquari trust evaluation for the authenticated subject represented by the supplied
  /// access token.
  public func evaluate(accessToken: String) async throws -> AquariTrustEvaluation {
    let wire = try await transport.requestJSON(
      EvaluationWire.self,
      path: "/api/v1/passport/trust/evaluation",
      headers: try bearerHeaders(accessToken)
    )

    let outcomes = try wire.outcomes.map { outcome in
      AquariTrustOutcome(
        type: try requireNonEmpty(outcome.type, field: "outcome type"),
        value: try requireNonEmpty(outcome.value, field: "outcome value"),
        supports: try outcome.supports.map(parseSupport)
      )
    }

    return AquariTrustEvaluation(
      evaluationID: try requireNonEmpty(wire.evaluationId, field: "evaluationId"),
      subjectID: try requireNonEmpty(wire.subjectId, field: "subjectId"),
      consumerApplicationID: try requireNonEmpty(
        wire.consumerApplicationId, field: "consumerApplicationId"),
      evaluatedAt: try requireISO8601(wire.evaluatedAt, field: "evaluatedAt"),
      outcomes: outcomes
    )
  }
}

private func parseSupport(_ wire: SupportWire) throws -> AquariTrustSupport {
  let scope = try wire.signal.scope.map {
    AquariTrustScope(
      type: try requireNonEmpty($0.type, field: "scope type"),
      id: try requireNonEmpty($0.id, field: "scope id")
    )
  }

  let signal = AquariTrustSignal(
    id: try requireNonEmpty(wire.signal.id, field: "signal id"),
    signalFamily: try requireNonEmpty(wire.signal.signalFamily, field: "signalFamily"),
    definitionID: wire.signal.definitionId,
    authority: AquariTrustAuthority(
      type: try requireNonEmpty(wire.signal.authority.type, field: "authority type"),
      id: try requireNonEmpty(wire.signal.authority.id, field: "authority id")
    ),
    scope: scope,
    issuedAt: try requireISO8601(wire.signal.issuedAt, field: "issuedAt"),
    expiresAt: try wire.signal.expiresAt.map { try requireISO8601($0, field: "expiresAt") }
  )

  return AquariTrustSupport(
    mappingID: try requireNonEmpty(wire.mappingId, field: "mappingId"),
    mappingVersion: wire.mappingVersion,
    trustedIssuerID: try requireNonEmpty(wire.trustedIssuerId, field: "trustedIssuerId"),
    signal: signal
  )
}
