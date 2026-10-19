#if canImport(AuthenticationServices) && canImport(Security)
  import Foundation
  @preconcurrency import AuthenticationServices
  import Security

  /// Defines the Keychain accessibility classes supported by the Aquari Apple adapter.
  public enum AquariKeychainAccessibility: Sendable {
    case afterFirstUnlockThisDeviceOnly
    case whenUnlockedThisDeviceOnly

    fileprivate var value: CFString {
      switch self {
      case .afterFirstUnlockThisDeviceOnly:
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
      case .whenUnlockedThisDeviceOnly:
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      }
    }
  }

  /// Configures the Keychain service, access group, and accessibility used by Aquari Apple storage.
  public struct AquariKeychainConfiguration: Sendable {
    public var service: String
    public var accessGroup: String?
    public var accessibility: AquariKeychainAccessibility

    public init(
      service: String = AquariKeychainConfiguration.defaultService,
      accessGroup: String? = nil,
      accessibility: AquariKeychainAccessibility = .afterFirstUnlockThisDeviceOnly
    ) {
      self.service = service
      self.accessGroup = accessGroup
      self.accessibility = accessibility
    }

    public static var defaultService: String {
      let identifier = Bundle.main.bundleIdentifier ?? "one.aquari.client"
      return "\(identifier).aquari"
    }
  }

  /// Stores the Aquari token set in the Apple Keychain.
  public struct AquariKeychainTokenStore: AquariTokenStoring {
    private let store: AquariKeychainJSONStore<AquariTokenSet>

    /// Creates a Keychain-backed token store for the supplied Aquari client identifier and Keychain
    /// configuration.
    public init(
      clientID: String,
      configuration: AquariKeychainConfiguration = .init()
    ) throws {
      self.store = try AquariKeychainJSONStore(
        service: configuration.service,
        account: "tokens:\(try validateKeychainNamespace(clientID))",
        accessGroup: configuration.accessGroup,
        accessibility: configuration.accessibility
      )
    }

    /// Reads the current value from protected Aquari storage. Returns no value when the store is empty.
    public func read() async throws -> AquariTokenSet? {
      try store.read()
    }

    /// Replaces the current value in protected Aquari storage.
    public func write(_ tokens: AquariTokenSet) async throws {
      try store.write(tokens)
    }

    /// Removes the current value from protected Aquari storage.
    public func clear() async throws {
      try store.clear()
    }
  }

  /// Stores the pending Aquari authorization transaction in the Apple Keychain.
  public struct AquariKeychainAuthorizationTransactionStore:
    AquariAuthorizationTransactionStoring
  {
    private let store: AquariKeychainJSONStore<AquariAuthorizationTransaction>

    /// Creates a Keychain-backed authorization transaction store for the supplied Aquari client
    /// identifier and Keychain configuration.
    public init(
      clientID: String,
      configuration: AquariKeychainConfiguration = .init()
    ) throws {
      self.store = try AquariKeychainJSONStore(
        service: configuration.service,
        account: "transaction:\(try validateKeychainNamespace(clientID))",
        accessGroup: configuration.accessGroup,
        accessibility: configuration.accessibility
      )
    }

    /// Reads the current value from protected Aquari storage. Returns no value when the store is empty.
    public func read() async throws -> AquariAuthorizationTransaction? {
      try store.read()
    }

    /// Replaces the current value in protected Aquari storage.
    public func write(_ transaction: AquariAuthorizationTransaction) async throws {
      try store.write(transaction)
    }

    /// Removes the current value from protected Aquari storage.
    public func clear() async throws {
      try store.clear()
    }
  }

  /// Defines the system authentication-session boundary used by the Aquari Apple adapter.
  @MainActor
  public protocol AquariBrowserAuthenticating: AnyObject {
    func authenticate(
      url: URL,
      callbackScheme: String,
      presentationAnchor: ASPresentationAnchor,
      prefersEphemeralSession: Bool
    ) async throws -> URL

    func cancel()
  }

  /// Runs Aquari authorization through ASWebAuthenticationSession.
  @MainActor
  public final class AquariASWebAuthenticationSessionAuthenticator:
    NSObject, AquariBrowserAuthenticating
  {
    private var session: ASWebAuthenticationSession?
    private var contextProvider: AquariPresentationContextProvider?

    public override init() {}

    /// Runs Aquari authorization in ASWebAuthenticationSession and returns the callback URL supplied by
    /// the operating system.
    public func authenticate(
      url: URL,
      callbackScheme: String,
      presentationAnchor: ASPresentationAnchor,
      prefersEphemeralSession: Bool = false
    ) async throws -> URL {
      guard session == nil else {
        throw AquariError.configuration(
          "An Aquari web authentication session is already in progress."
        )
      }
      guard !callbackScheme.isEmpty else {
        throw AquariError.configuration(
          "Aquari web authentication requires a custom callback scheme."
        )
      }

      let provider = AquariPresentationContextProvider(anchor: presentationAnchor)
      contextProvider = provider

      return try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { continuation in
          let completion: ASWebAuthenticationSession.CompletionHandler = {
            [weak self] callbackURL, error in
            Task { @MainActor in
              self?.session = nil
              self?.contextProvider = nil
            }

            if let callbackURL {
              continuation.resume(returning: callbackURL)
              return
            }

            if let authError = error as? ASWebAuthenticationSessionError,
              authError.code == .canceledLogin
            {
              continuation.resume(throwing: AquariError.cancelled)
              return
            }

            continuation.resume(
              throwing: AquariError.transport(
                "Aquari system-browser authentication did not return a callback URL."
              )
            )
          }

          let newSession: ASWebAuthenticationSession
          if #available(iOS 17.4, macOS 14.4, macCatalyst 17.4, *) {
            newSession = ASWebAuthenticationSession(
              url: url,
              callback: .customScheme(callbackScheme),
              completionHandler: completion
            )
          } else {
            newSession = ASWebAuthenticationSession(
              url: url,
              callbackURLScheme: callbackScheme,
              completionHandler: completion
            )
          }

          newSession.presentationContextProvider = provider
          newSession.prefersEphemeralWebBrowserSession = prefersEphemeralSession
          session = newSession

          guard newSession.start() else {
            session = nil
            contextProvider = nil
            continuation.resume(
              throwing: AquariError.transport(
                "Aquari system-browser authentication could not start."
              )
            )
            return
          }
        }
      } onCancel: {
        Task { @MainActor [weak self] in
          self?.cancel()
        }
      }
    }

    /// Cancels the active system authentication session and clears its presentation state.
    public func cancel() {
      session?.cancel()
      session = nil
      contextProvider = nil
    }
  }

  /// Coordinates ASWebAuthenticationSession, Keychain-backed state, session restore, refresh,
  /// Passport, trust, and sign-out on Apple platforms.
  @MainActor
  public final class AquariAppleClient {
    /// Gets the underlying cross-platform Aquari client.
    public let core: AquariClient
    /// Gets the session manager that owns protected local authorization state.
    public let sessions: AquariSessionManager

    private let browser: any AquariBrowserAuthenticating

    /// Creates an Apple client. Default construction uses Keychain-backed stores and
    /// ASWebAuthenticationSession; advanced initializers can supply application-owned stores and
    /// browser adapters.
    public convenience init(
      options: AquariClientOptions,
      keychain: AquariKeychainConfiguration = .init()
    ) throws {
      try self.init(
        options: options,
        keychain: keychain,
        browser: AquariASWebAuthenticationSessionAuthenticator()
      )
    }

    /// Creates an Apple client. Default construction uses Keychain-backed stores and
    /// ASWebAuthenticationSession; advanced initializers can supply application-owned stores and
    /// browser adapters.
    public init(
      options: AquariClientOptions,
      keychain: AquariKeychainConfiguration = .init(),
      browser: any AquariBrowserAuthenticating
    ) throws {
      let core = try AquariClient(options: options)
      let tokens = try AquariKeychainTokenStore(
        clientID: core.clientID,
        configuration: keychain
      )
      let transactions = try AquariKeychainAuthorizationTransactionStore(
        clientID: core.clientID,
        configuration: keychain
      )

      self.core = core
      self.sessions = AquariSessionManager(
        client: core,
        tokenStore: tokens,
        transactionStore: transactions
      )
      self.browser = browser
    }

    /// Creates an Apple client. Default construction uses Keychain-backed stores and
    /// ASWebAuthenticationSession; advanced initializers can supply application-owned stores and
    /// browser adapters.
    public init(
      core: AquariClient,
      tokenStore: any AquariTokenStoring,
      transactionStore: any AquariAuthorizationTransactionStoring,
      browser: any AquariBrowserAuthenticating
    ) {
      self.core = core
      self.sessions = AquariSessionManager(
        client: core,
        tokenStore: tokenStore,
        transactionStore: transactionStore
      )
      self.browser = browser
    }

    /// Starts Aquari sign-in through the system browser and completes the Authorization Code with S256
    /// PKCE flow when the callback returns.
    public func signIn(
      presentationAnchor: ASPresentationAnchor,
      prompt: AquariAuthorizationPrompt? = nil,
      prefersEphemeralBrowserSession: Bool = false
    ) async throws -> AquariAuthorizationResult {
      let begin = try await sessions.prepareAuthorization(prompt: prompt)
      guard let scheme = core.redirectURI.scheme,
        !scheme.isEmpty,
        scheme.lowercased() != "http",
        scheme.lowercased() != "https"
      else {
        try? await sessions.cancelAuthorization()
        throw AquariError.configuration(
          "AquariAppleClient currently requires a custom-scheme redirect URI."
        )
      }

      do {
        let callbackURL = try await browser.authenticate(
          url: begin.url,
          callbackScheme: scheme,
          presentationAnchor: presentationAnchor,
          prefersEphemeralSession: prefersEphemeralBrowserSession
        )
        return try await sessions.completeAuthorization(callbackURL: callbackURL)
      } catch {
        try? await sessions.cancelAuthorization()
        throw error
      }
    }

    /// Completes the stored authorization transaction. The SDK validates callback state and issuer
    /// data, exchanges the code, validates the returned identity, stores the new token set, and clears
    /// pending transaction state.
    public func completeAuthorization(callbackURL: URL) async throws -> AquariAuthorizationResult {
      try await sessions.completeAuthorization(callbackURL: callbackURL)
    }

    /// Restores session state from protected storage. If the access token expires within the refresh
    /// leeway, the SDK refreshes the token set first. The operation returns no session when storage is
    /// empty or no refresh token can recover an expiring session.
    public func restoreSession(refreshLeeway: TimeInterval = 60) async throws -> AquariSession? {
      try await sessions.restoreSession(refreshLeeway: refreshLeeway)
    }

    /// Refreshes the stored Aquari session, replaces the token set, resolves UserInfo, and preserves
    /// subject continuity.
    public func refreshSession() async throws -> AquariSession {
      try await sessions.refreshSession()
    }

    /// Reads the current token set from protected storage without printing or exposing token values to
    /// logs.
    public func currentTokens() async throws -> AquariTokenSet? {
      try await sessions.currentTokens()
    }

    /// Reads the connected Passport for the current authenticated subject.
    public func passport() async throws -> AquariPassport {
      try await sessions.passport()
    }

    /// Reads Passport signals for the current authenticated subject and applies the supplied filters.
    public func passportSignals(filters: AquariPassportSignalFilters = .init()) async throws
      -> AquariPassportSignalPage
    {
      try await sessions.passportSignals(filters: filters)
    }

    /// Evaluates Aquari trust for the current authenticated subject and consumer application.
    public func trustEvaluation() async throws -> AquariTrustEvaluation {
      try await sessions.trustEvaluation()
    }

    /// Reads public Passport data for the supplied Aquari handle.
    public func publicPassport(handle: String) async throws -> AquariPublicPassport {
      try await sessions.publicPassport(handle: handle)
    }

    /// Clears local Aquari session and pending authorization state. This operation does not grant or
    /// revoke application permissions.
    public func signOut() async throws {
      browser.cancel()
      try await sessions.signOut()
    }
  }

  private final class AquariPresentationContextProvider:
    NSObject, ASWebAuthenticationPresentationContextProviding
  {
    let anchor: ASPresentationAnchor

    init(anchor: ASPresentationAnchor) {
      self.anchor = anchor
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
      anchor
    }
  }

  private struct AquariKeychainJSONStore<Value: Codable & Sendable>: Sendable {
    let service: String
    let account: String
    let accessGroup: String?
    let accessibility: AquariKeychainAccessibility

    init(
      service: String,
      account: String,
      accessGroup: String?,
      accessibility: AquariKeychainAccessibility
    ) throws {
      guard !service.isEmpty,
        service == service.trimmingCharacters(in: .whitespacesAndNewlines)
      else {
        throw AquariError.configuration(
          "Aquari Keychain service must be a non-empty normalized string."
        )
      }
      guard !account.isEmpty else {
        throw AquariError.configuration(
          "Aquari Keychain account must not be empty."
        )
      }
      if let accessGroup {
        guard !accessGroup.isEmpty,
          accessGroup == accessGroup.trimmingCharacters(in: .whitespacesAndNewlines)
        else {
          throw AquariError.configuration(
            "Aquari Keychain access group must be a non-empty normalized string."
          )
        }
      }

      self.service = service
      self.account = account
      self.accessGroup = accessGroup
      self.accessibility = accessibility
    }

    func read() throws -> Value? {
      var query = baseQuery
      query[kSecReturnData as String] = kCFBooleanTrue
      query[kSecMatchLimit as String] = kSecMatchLimitOne

      var item: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &item)
      if status == errSecItemNotFound {
        return nil
      }
      guard status == errSecSuccess, let data = item as? Data else {
        throw keychainError(operation: "read", status: status)
      }

      do {
        return try JSONDecoder().decode(Value.self, from: data)
      } catch {
        throw AquariError.secureStorage(
          "Aquari Keychain data could not be decoded."
        )
      }
    }

    func write(_ value: Value) throws {
      let data: Data
      do {
        data = try JSONEncoder().encode(value)
      } catch {
        throw AquariError.secureStorage(
          "Aquari Keychain value could not be encoded."
        )
      }

      let updateStatus = SecItemUpdate(
        baseQuery as CFDictionary,
        [kSecValueData as String: data] as CFDictionary
      )

      if updateStatus == errSecSuccess {
        return
      }

      if updateStatus != errSecItemNotFound {
        throw keychainError(operation: "update", status: updateStatus)
      }

      var add = baseQuery
      add[kSecValueData as String] = data
      add[kSecAttrAccessible as String] = accessibility.value

      let addStatus = SecItemAdd(add as CFDictionary, nil)
      guard addStatus == errSecSuccess else {
        throw keychainError(operation: "write", status: addStatus)
      }
    }

    func clear() throws {
      let status = SecItemDelete(baseQuery as CFDictionary)
      guard status == errSecSuccess || status == errSecItemNotFound else {
        throw keychainError(operation: "delete", status: status)
      }
    }

    private var baseQuery: [String: Any] {
      var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
      ]
      if let accessGroup {
        query[kSecAttrAccessGroup as String] = accessGroup
      }
      return query
    }
  }

  private func validateKeychainNamespace(_ value: String) throws -> String {
    guard !value.isEmpty,
      value == value.trimmingCharacters(in: .whitespacesAndNewlines)
    else {
      throw AquariError.configuration(
        "Aquari Keychain client namespace must be a non-empty normalized string."
      )
    }
    return value
  }

  private func keychainError(operation: String, status: OSStatus) -> AquariError {
    let message =
      SecCopyErrorMessageString(status, nil) as String?
      ?? "OSStatus \(status)"
    return .secureStorage(
      "Aquari Keychain \(operation) failed: \(message)."
    )
  }
#endif
