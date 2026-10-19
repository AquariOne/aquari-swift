import Foundation
import Testing

@testable import AquariOne

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

@Suite("Aquari One Swift v1 core")
struct AquariOneTests {
  @Test func configurationRejectsRemoteHTTP() throws {
    let options = AquariClientOptions(
      issuer: URL(string: "http://example.com")!, clientID: "client",
      redirectURI: URL(string: "app:/oauth2redirect")!, scopes: [AquariScopes.openID])
    #expect(throws: AquariError.self) { _ = try AquariClient(options: options) }
  }

  @Test func pkceMatchesRFC7636Vector() throws {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    #expect(
      try AquariPKCE.challenge(for: verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    let pair = try AquariPKCE.create()
    #expect(pair.codeVerifier.count == 64)
    #expect(pair.codeChallenge.count == 43)
  }

  @Test func discoveryAndBeginAreStrict() async throws {
    let fake = FakeHTTPClient()
    await fake.set(path: "/.well-known/openid-configuration", json: discoveryJSON())
    let client = try AquariClient(options: options(http: fake))
    let discovery = try await client.auth.discover()
    #expect(discovery.issuer == "https://dev.api.aquari.one/")
    let begin = try await client.auth.begin(prompt: .consent)
    #expect(begin.transaction.state.count == 43)
    #expect(
      URLComponents(url: begin.url, resolvingAgainstBaseURL: false)?.queryItems?.contains(
        URLQueryItem(name: "code_challenge_method", value: "S256")) == true)
  }

  @Test func stateMismatchFailsBeforeTokenExchange() async throws {
    let fake = FakeHTTPClient()
    await fake.set(path: "/.well-known/openid-configuration", json: discoveryJSON())
    let client = try AquariClient(options: options(http: fake))
    let begin = try await client.auth.begin()
    let callback = URL(
      string:
        "one.aquari.swift.test:/oauth2redirect?code=x&state=wrong&iss=https%3A%2F%2Fdev.api.aquari.one%2F"
    )!
    await #expect(throws: AquariError.self) {
      _ = try await client.auth.complete(callbackURL: callback, transaction: begin.transaction)
    }
  }

  @Test func fullOAuthRefreshPassportTrustCore() async throws {
    let fake = FakeHTTPClient()
    await fake.set(path: "/.well-known/openid-configuration", json: discoveryJSON())
    await fake.set(
      path: "/jwks", json: #"{"keys":[{"kty":"RSA","kid":"k1","alg":"RS256","n":"AQ","e":"AQAB"}]}"#
    )
    let client = try AquariClient(
      options: options(http: fake), signatureVerifier: AlwaysValidSignatureVerifier())
    let begin = try await client.auth.begin()
    let jwt = makeJWT(nonce: begin.transaction.nonce)
    await fake.set(
      path: "/connect/token",
      json:
        "{\"access_token\":\"a1\",\"id_token\":\"\(jwt)\",\"refresh_token\":\"r1\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"openid profile email offline_access passport.read\"}"
    )
    await fake.set(
      path: "/connect/userinfo",
      json: #"{"sub":"sub-1","preferred_username":"@test.aquari.one","email_verified":true}"#)
    await fake.set(
      path: "/api/v1/passport",
      json:
        #"{"passport":{"id":"p1","passportNumber":"AQ-1","subjectId":"sub-1","profile":{"displayName":"Test","handle":"@test.aquari.one","publicUrl":"https://aquari.one/test","verified":true,"visibility":"public"},"signals":{"total":0}}}"#
    )
    await fake.set(
      path: "/api/v1/passport/signals", json: #"{"items":[],"page":{"hasMore":false}}"#)
    await fake.set(
      path: "/api/v1/public/passports/@test.aquari.one",
      json:
        #"{"displayName":"Test","handle":"@test.aquari.one","publicUrl":"https://aquari.one/test","verified":true,"signals":[]}"#
    )
    await fake.set(
      path: "/api/v1/passport/trust/evaluation",
      json:
        #"{"evaluationId":"e1","subjectId":"sub-1","consumerApplicationId":"app1","evaluatedAt":"2026-09-28T00:00:00Z","outcomes":[]}"#
    )
    let callback = URL(
      string:
        "one.aquari.swift.test:/oauth2redirect?code=c1&state=\(begin.transaction.state)&iss=https%3A%2F%2Fdev.api.aquari.one%2F"
    )!
    let result = try await client.auth.complete(
      callbackURL: callback, transaction: begin.transaction)
    #expect(result.tokens.subject == "sub-1")
    #expect(try await client.auth.userInfo(result.tokens).subject == "sub-1")
    let refreshedJWT = makeJWT(nonce: nil)
    await fake.set(
      path: "/connect/token",
      json:
        "{\"access_token\":\"a2\",\"id_token\":\"\(refreshedJWT)\",\"refresh_token\":\"r2\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
    )
    let refreshed = try await client.auth.refresh(result.tokens)
    #expect(refreshed.refreshToken == "r2")
    #expect(try await client.passport.get(accessToken: refreshed.accessToken).subjectID == "sub-1")
    #expect(
      try await client.passport.signals.list(accessToken: refreshed.accessToken).items.isEmpty)
    #expect(
      try await client.passport.getPublic(handle: "@test.aquari.one").handle == "@test.aquari.one")
    #expect(try await client.trust.evaluate(accessToken: refreshed.accessToken).outcomes.isEmpty)
  }
  @Test func sessionManagerPersistsRestoresRefreshesAndSignsOut() async throws {
    let fake = FakeHTTPClient()
    await fake.set(path: "/.well-known/openid-configuration", json: discoveryJSON())
    await fake.set(
      path: "/jwks", json: #"{"keys":[{"kty":"RSA","kid":"k1","alg":"RS256","n":"AQ","e":"AQAB"}]}"#
    )
    let client = try AquariClient(
      options: options(http: fake), signatureVerifier: AlwaysValidSignatureVerifier())
    let tokenStore = MemoryTokenStore()
    let transactionStore = MemoryTransactionStore()
    let manager = AquariSessionManager(
      client: client, tokenStore: tokenStore, transactionStore: transactionStore)

    let begin = try await manager.prepareAuthorization()
    #expect(await transactionStore.hasValue())

    let jwt = makeJWT(nonce: begin.transaction.nonce)
    await fake.set(
      path: "/connect/token",
      json:
        "{\"access_token\":\"a1\",\"id_token\":\"\(jwt)\",\"refresh_token\":\"r1\",\"token_type\":\"Bearer\",\"expires_in\":1,\"scope\":\"openid profile email offline_access passport.read\"}"
    )
    let callback = URL(
      string:
        "one.aquari.swift.test:/oauth2redirect?code=c1&state=\(begin.transaction.state)&iss=https%3A%2F%2Fdev.api.aquari.one%2F"
    )!
    let result = try await manager.completeAuthorization(callbackURL: callback)
    #expect(result.tokens.subject == "sub-1")
    #expect(!(await transactionStore.hasValue()))
    #expect(await tokenStore.hasValue())

    await fake.set(
      path: "/connect/userinfo",
      json: #"{"sub":"sub-1","preferred_username":"@test.aquari.one","email_verified":true}"#)
    let refreshedJWT = makeJWT(nonce: nil)
    await fake.set(
      path: "/connect/token",
      json:
        "{\"access_token\":\"a2\",\"id_token\":\"\(refreshedJWT)\",\"refresh_token\":\"r2\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
    )
    let restored = try await manager.restoreSession(refreshLeeway: 60)
    #expect(restored?.tokens.refreshToken == "r2")
    #expect(restored?.identity.subject == "sub-1")

    try await manager.signOut()
    #expect(!(await tokenStore.hasValue()))
    #expect(!(await transactionStore.hasValue()))
  }

}

private actor MemoryTokenStore: AquariTokenStoring {
  private var value: AquariTokenSet?
  func read() async throws -> AquariTokenSet? { value }
  func write(_ tokens: AquariTokenSet) async throws { value = tokens }
  func clear() async throws { value = nil }
  func hasValue() -> Bool { value != nil }
}

private actor MemoryTransactionStore: AquariAuthorizationTransactionStoring {
  private var value: AquariAuthorizationTransaction?
  func read() async throws -> AquariAuthorizationTransaction? { value }
  func write(_ transaction: AquariAuthorizationTransaction) async throws { value = transaction }
  func clear() async throws { value = nil }
  func hasValue() -> Bool { value != nil }
}

private final class FakeHTTPClient: AquariHTTPClient, @unchecked Sendable {
  private let lock = NSLock()
  private var bodies: [String: Data] = [:]
  func set(path: String, json: String) async { lock.withLock { bodies[path] = Data(json.utf8) } }
  func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
    let path = request.url!.path + (request.url!.query.map { "?" + $0 } ?? "")
    let body = lock.withLock { bodies[path] ?? bodies[request.url!.path] }
    guard let body else { throw URLError(.badServerResponse) }
    return (
      body,
      HTTPURLResponse(
        url: request.url!, statusCode: 200, httpVersion: nil,
        headerFields: ["Content-Type": "application/json"])!
    )
  }
}
private struct AlwaysValidSignatureVerifier: AquariRS256SignatureVerifying {
  func verify(message: Data, signature: Data, key: AquariRSAJWK) throws -> Bool { true }
}
private func options(http: any AquariHTTPClient) -> AquariClientOptions {
  AquariClientOptions(
    issuer: URL(string: "https://dev.api.aquari.one/")!, clientID: "public-client",
    redirectURI: URL(string: "one.aquari.swift.test:/oauth2redirect")!,
    scopes: [
      AquariScopes.openID, AquariScopes.profile, AquariScopes.email, AquariScopes.offlineAccess,
      AquariScopes.passportRead,
    ], httpClient: http)
}
private func discoveryJSON() -> String {
  #"{"issuer":"https://dev.api.aquari.one/","authorization_endpoint":"https://auth.dev.aquari.one/connect/authorize","token_endpoint":"https://dev.api.aquari.one/connect/token","userinfo_endpoint":"https://dev.api.aquari.one/connect/userinfo","jwks_uri":"https://dev.api.aquari.one/jwks","grant_types_supported":["authorization_code","refresh_token"],"response_types_supported":["code"],"code_challenge_methods_supported":["S256"],"id_token_signing_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["none"],"authorization_response_iss_parameter_supported":true}"#
}
private func makeJWT(nonce: String?) -> String {
  var p: [String: Any] = [
    "iss": "https://dev.api.aquari.one/", "aud": "public-client", "sub": "sub-1",
    "exp": Date().addingTimeInterval(3600).timeIntervalSince1970,
    "iat": Date().timeIntervalSince1970, "preferred_username": "@test.aquari.one",
  ]
  if let nonce { p["nonce"] = nonce }
  let h = try! JSONSerialization.data(withJSONObject: ["alg": "RS256", "kid": "k1"])
  let d = try! JSONSerialization.data(withJSONObject: p)
  return "\(base64URLEncode(h)).\(base64URLEncode(d)).\(base64URLEncode(Data("sig".utf8)))"
}

@Test func retryAfterRejectsMalformedValuesAndBoundsLargeSeconds() {
  let now = Date(timeIntervalSince1970: 1_791_158_400)
  for value in ["-1", "+1", "0x10", "1.5", "", "not-a-date"] {
    #expect(parseRetryAfter(value, now: now) == nil)
  }
  #expect(parseRetryAfter("12", now: now) == 12)
  for value in [
    "Mon, 05 Oct 2026 00:00:12 GMT", "Monday, 05-Oct-26 00:00:12 GMT", "Mon Oct  5 00:00:12 2026",
  ] {
    #expect(parseRetryAfter(value, now: now) == 12)
  }
  #expect(parseRetryAfter(String(repeating: "9", count: 400), now: now) == 9_007_199_254)
}
