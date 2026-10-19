import Foundation

/// Contains validated OpenID Connect discovery metadata for the configured Aquari issuer.
public struct AquariOIDCDiscovery: Sendable, Equatable {
  public let issuer: String
  public let authorizationEndpoint: URL
  public let tokenEndpoint: URL
  public let userInfoEndpoint: URL
  public let jwksURI: URL
  public let grantTypesSupported: [String]
  public let responseTypesSupported: [String]
  public let codeChallengeMethodsSupported: [String]
  public let idTokenSigningAlgorithmsSupported: [String]
  public let tokenEndpointAuthMethodsSupported: [String]
  public let authorizationResponseIssuerParameterSupported: Bool
}

private struct DiscoveryWire: Decodable, Sendable {
  let issuer: String
  let authorizationEndpoint: String
  let tokenEndpoint: String
  let userInfoEndpoint: String
  let jwksURI: String
  let grantTypesSupported: [String]
  let responseTypesSupported: [String]
  let codeChallengeMethodsSupported: [String]
  let idTokenSigningAlgorithmsSupported: [String]
  let tokenEndpointAuthMethodsSupported: [String]?
  let authorizationResponseIssuerParameterSupported: Bool?
  enum CodingKeys: String, CodingKey {
    case issuer
    case authorizationEndpoint = "authorization_endpoint"
    case tokenEndpoint = "token_endpoint"
    case userInfoEndpoint = "userinfo_endpoint"
    case jwksURI = "jwks_uri"
    case grantTypesSupported = "grant_types_supported"
    case responseTypesSupported = "response_types_supported"
    case codeChallengeMethodsSupported = "code_challenge_methods_supported"
    case idTokenSigningAlgorithmsSupported = "id_token_signing_alg_values_supported"
    case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
    case authorizationResponseIssuerParameterSupported =
      "authorization_response_iss_parameter_supported"
  }
}

func discoverOIDC(transport: AquariHTTPTransport, configuredIssuer: String) async throws
  -> AquariOIDCDiscovery
{
  let wire = try await transport.requestJSON(
    DiscoveryWire.self, path: "/.well-known/openid-configuration")
  guard wire.issuer == configuredIssuer else {
    throw AquariError.configuration(
      "Aquari OIDC discovery issuer does not exactly match the configured issuer.")
  }
  try require(
    wire.grantTypesSupported, contains: "authorization_code",
    message: "Aquari OIDC discovery does not advertise the authorization-code grant.")
  try require(
    wire.grantTypesSupported, contains: "refresh_token",
    message: "Aquari OIDC discovery does not advertise the refresh-token grant.")
  try require(
    wire.responseTypesSupported, contains: "code",
    message: "Aquari OIDC discovery does not advertise the code response type.")
  try require(
    wire.codeChallengeMethodsSupported, contains: "S256",
    message: "Aquari OIDC discovery does not advertise S256 PKCE.")
  try require(
    wire.idTokenSigningAlgorithmsSupported, contains: "RS256",
    message: "Aquari OIDC discovery does not advertise RS256 ID-token signing.")

  return AquariOIDCDiscovery(
    issuer: wire.issuer,
    authorizationEndpoint: try validateOIDCEndpoint(
      wire.authorizationEndpoint, name: "authorization_endpoint"),
    tokenEndpoint: try validateOIDCEndpoint(wire.tokenEndpoint, name: "token_endpoint"),
    userInfoEndpoint: try validateOIDCEndpoint(wire.userInfoEndpoint, name: "userinfo_endpoint"),
    jwksURI: try validateOIDCEndpoint(wire.jwksURI, name: "jwks_uri"),
    grantTypesSupported: wire.grantTypesSupported,
    responseTypesSupported: wire.responseTypesSupported,
    codeChallengeMethodsSupported: wire.codeChallengeMethodsSupported,
    idTokenSigningAlgorithmsSupported: wire.idTokenSigningAlgorithmsSupported,
    tokenEndpointAuthMethodsSupported: wire.tokenEndpointAuthMethodsSupported ?? [],
    authorizationResponseIssuerParameterSupported: wire
      .authorizationResponseIssuerParameterSupported ?? false
  )
}

private func require(_ values: [String], contains required: String, message: String) throws {
  guard values.contains(required) else { throw AquariError.configuration(message) }
}

private func validateOIDCEndpoint(_ raw: String, name: String) throws -> URL {
  guard !raw.isEmpty, raw == raw.trimmingCharacters(in: .whitespacesAndNewlines),
    let url = URL(string: raw),
    let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
    let scheme = components.scheme?.lowercased(), components.host != nil
  else {
    throw AquariError.configuration(
      "Aquari OIDC discovery field '\(name)' must be an absolute URL.")
  }
  guard scheme == "https" || (scheme == "http" && isLocalDevelopmentHost(components.host ?? ""))
  else {
    throw AquariError.configuration(
      "Aquari OIDC discovery field '\(name)' must use HTTPS outside local development.")
  }
  guard components.user == nil, components.password == nil, components.fragment == nil else {
    throw AquariError.configuration(
      "Aquari OIDC discovery field '\(name)' contains unsupported URL components.")
  }
  return url
}
