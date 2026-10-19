import Foundation

/// Contains the current Aquari token set and subject-bound identity.
public struct AquariSession: Sendable, Equatable {
  /// Gets the current subject-bound token set. Do not log token values.
  public let tokens: AquariTokenSet
  /// Gets the subject-bound Aquari identity.
  public let identity: AquariIdentity

  public init(tokens: AquariTokenSet, identity: AquariIdentity) {
    self.tokens = tokens
    self.identity = identity
  }
}

/// Defines protected storage for the current Aquari token set.
public protocol AquariTokenStoring: Sendable {
  func read() async throws -> AquariTokenSet?
  func write(_ tokens: AquariTokenSet) async throws
  func clear() async throws
}

/// Defines protected storage for the pending Aquari authorization transaction.
public protocol AquariAuthorizationTransactionStoring: Sendable {
  func read() async throws -> AquariAuthorizationTransaction?
  func write(_ transaction: AquariAuthorizationTransaction) async throws
  func clear() async throws
}

/// Coordinates authorization state, token storage, session restore, refresh-token rotation,
/// Passport, trust, and sign-out.
public actor AquariSessionManager {
  public let client: AquariClient

  private let tokenStore: any AquariTokenStoring
  private let transactionStore: any AquariAuthorizationTransactionStoring

  /// Creates a session manager from a core Aquari client and application-provided protected token and
  /// transaction stores.
  public init(
    client: AquariClient,
    tokenStore: any AquariTokenStoring,
    transactionStore: any AquariAuthorizationTransactionStoring
  ) {
    self.client = client
    self.tokenStore = tokenStore
    self.transactionStore = transactionStore
  }

  /// Creates and stores a pending Authorization Code transaction before the application opens the
  /// system browser.
  @discardableResult
  public func prepareAuthorization(prompt: AquariAuthorizationPrompt? = nil) async throws
    -> AquariBeginAuthorizationResult
  {
    let begin = try await client.auth.begin(prompt: prompt)
    try await transactionStore.write(begin.transaction)
    return begin
  }

  /// Completes the stored authorization transaction. The SDK validates callback state and issuer
  /// data, exchanges the code, validates the returned identity, stores the new token set, and clears
  /// pending transaction state.
  public func completeAuthorization(callbackURL: URL) async throws -> AquariAuthorizationResult {
    guard let transaction = try await transactionStore.read() else {
      throw AquariError.oauth(
        AquariOAuthError(
          code: "missing_transaction",
          message: "Aquari authorization callback does not have a pending transaction."
        )
      )
    }

    let result = try await client.auth.complete(
      callbackURL: callbackURL,
      transaction: transaction
    )
    try await tokenStore.write(result.tokens)
    try await transactionStore.clear()
    return result
  }

  /// Clears the pending authorization transaction from protected storage.
  public func cancelAuthorization() async throws {
    try await transactionStore.clear()
  }

  /// Reads the current token set from protected storage without printing or exposing token values to
  /// logs.
  public func currentTokens() async throws -> AquariTokenSet? {
    try await tokenStore.read()
  }

  /// Restores session state from protected storage. If the access token expires within the refresh
  /// leeway, the SDK refreshes the token set first. The operation returns no session when storage is
  /// empty or no refresh token can recover an expiring session.
  public func restoreSession(refreshLeeway: TimeInterval = 60) async throws -> AquariSession? {
    guard refreshLeeway.isFinite, refreshLeeway >= 0 else {
      throw AquariError.configuration("refreshLeeway must be non-negative.")
    }

    guard var tokens = try await tokenStore.read() else {
      return nil
    }

    if tokens.expiresAt <= Date().addingTimeInterval(refreshLeeway) {
      guard tokens.refreshToken != nil else {
        try await tokenStore.clear()
        return nil
      }
      tokens = try await client.auth.refresh(tokens)
      try await tokenStore.write(tokens)
    }

    let identity = try await client.auth.userInfo(tokens)
    return AquariSession(tokens: tokens, identity: identity)
  }

  /// Refreshes the stored Aquari session, replaces the token set, resolves UserInfo, and preserves
  /// subject continuity.
  public func refreshSession() async throws -> AquariSession {
    guard let current = try await tokenStore.read() else {
      throw missingSessionError()
    }
    let refreshed = try await client.auth.refresh(current)
    try await tokenStore.write(refreshed)
    let identity = try await client.auth.userInfo(refreshed)
    return AquariSession(tokens: refreshed, identity: identity)
  }

  /// Reads the connected Passport for the current authenticated subject.
  public func passport() async throws -> AquariPassport {
    guard let tokens = try await tokenStore.read() else {
      throw missingSessionError()
    }
    return try await client.passport.get(accessToken: tokens.accessToken)
  }

  /// Reads Passport signals for the current authenticated subject and applies the supplied filters.
  public func passportSignals(filters: AquariPassportSignalFilters = .init()) async throws
    -> AquariPassportSignalPage
  {
    guard let tokens = try await tokenStore.read() else {
      throw missingSessionError()
    }
    return try await client.passport.signals.list(
      accessToken: tokens.accessToken,
      filters: filters
    )
  }

  /// Evaluates Aquari trust for the current authenticated subject and consumer application.
  public func trustEvaluation() async throws -> AquariTrustEvaluation {
    guard let tokens = try await tokenStore.read() else {
      throw missingSessionError()
    }
    return try await client.trust.evaluate(accessToken: tokens.accessToken)
  }

  /// Reads public Passport data for the supplied Aquari handle.
  public func publicPassport(handle: String) async throws -> AquariPublicPassport {
    try await client.passport.getPublic(handle: handle)
  }

  /// Clears local Aquari session and pending authorization state. This operation does not grant or
  /// revoke application permissions.
  public func signOut() async throws {
    var firstError: (any Error)?
    do {
      try await tokenStore.clear()
    } catch {
      firstError = error
    }

    do {
      try await transactionStore.clear()
    } catch {
      if firstError == nil {
        firstError = error
      }
    }

    if let firstError {
      throw firstError
    }
  }
}

private func missingSessionError() -> AquariError {
  .oauth(
    AquariOAuthError(
      code: "missing_session",
      message: "Aquari does not have a stored authenticated session."
    )
  )
}
