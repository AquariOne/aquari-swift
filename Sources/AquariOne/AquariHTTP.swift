import Foundation

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

/// Defines the HTTP execution boundary used by the Swift Aquari transport.
public protocol AquariHTTPClient: Sendable {
  func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping @Sendable (URLRequest?) -> Void
  ) {
    completionHandler(nil)
  }
}

/// Executes Aquari HTTP requests with URLSession.
public final class AquariURLSessionHTTPClient: AquariHTTPClient, @unchecked Sendable {
  private let session: URLSession

  /// Creates the default URLSession-backed Swift HTTP client.
  public init() {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.httpShouldSetCookies = false
    configuration.httpCookieAcceptPolicy = .never
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    self.session = URLSession(
      configuration: configuration,
      delegate: NoRedirectDelegate(),
      delegateQueue: nil
    )
  }

  /// Executes the URL request and returns response bytes with the HTTP response metadata.
  public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
    let (data, response) = try await session.data(for: request)
    guard let http = response as? HTTPURLResponse else {
      throw AquariError.transport("Aquari request did not return an HTTP response.")
    }
    return (data, http)
  }
}

/// Lists the HTTP methods used by the Aquari Swift transport.
public enum AquariHTTPMethod: String, Sendable {
  case get = "GET"
  case post = "POST"
  case put = "PUT"
  case patch = "PATCH"
  case delete = "DELETE"
  case head = "HEAD"
  case options = "OPTIONS"
}

/// Controls whether the Aquari HTTP transport retries a request.
public enum AquariRetryMode: Sendable {
  case auto
  case never
  case idempotent
}

struct AquariHTTPTransport: Sendable {
  let baseURL: URL
  let timeout: TimeInterval
  let maxRetries: Int
  let maxRetryDelay: TimeInterval
  let client: any AquariHTTPClient

  func requestData(
    path: String,
    method: AquariHTTPMethod = .get,
    headers: [String: String] = [:],
    body: Data? = nil,
    retryMode: AquariRetryMode = .auto
  ) async throws -> (Data, HTTPURLResponse) {
    guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL else {
      throw AquariError.configuration("Aquari request path is invalid.")
    }
    return try await requestData(
      url: url, method: method, headers: headers, body: body, retryMode: retryMode)
  }

  func requestData(
    url: URL,
    method: AquariHTTPMethod = .get,
    headers: [String: String] = [:],
    body: Data? = nil,
    retryMode: AquariRetryMode = .auto
  ) async throws -> (Data, HTTPURLResponse) {
    let retryable = isRetryable(method: method, mode: retryMode)
    var attempt = 0

    while true {
      try Task.checkCancellation()
      var request = URLRequest(url: url, timeoutInterval: timeout)
      request.httpMethod = method.rawValue
      request.httpBody = body
      request.setValue("application/json", forHTTPHeaderField: "Accept")
      for (name, value) in headers {
        request.setValue(value, forHTTPHeaderField: name)
      }

      do {
        let (data, response) = try await client.data(for: request)
        if (200..<300).contains(response.statusCode) {
          return (data, response)
        }

        let error = parseAPIError(data: data, response: response)
        if retryable,
          attempt < maxRetries,
          isRetryableStatus(response.statusCode)
        {
          let delay = retryDelay(response: response, attempt: attempt)
          if delay <= maxRetryDelay {
            try await sleep(delay)
            attempt += 1
            continue
          }
        }
        throw AquariError.api(error)
      } catch is CancellationError {
        throw AquariError.cancelled
      } catch let error as AquariError {
        if case .api = error { throw error }
        if case .cancelled = error { throw error }
        if retryable, attempt < maxRetries {
          let delay = backoffDelay(attempt: attempt)
          if delay <= maxRetryDelay {
            try await sleep(delay)
            attempt += 1
            continue
          }
        }
        throw error
      } catch let error as URLError {
        if error.code == .cancelled { throw AquariError.cancelled }
        if retryable, attempt < maxRetries {
          let delay = backoffDelay(attempt: attempt)
          if delay <= maxRetryDelay {
            try await sleep(delay)
            attempt += 1
            continue
          }
        }
        if error.code == .timedOut { throw AquariError.timeout(timeout) }
        throw AquariError.transport(
          "Aquari request failed before a valid API response was received.")
      } catch {
        if retryable, attempt < maxRetries {
          let delay = backoffDelay(attempt: attempt)
          if delay <= maxRetryDelay {
            try await sleep(delay)
            attempt += 1
            continue
          }
        }
        throw AquariError.transport(
          "Aquari request failed before a valid API response was received.")
      }
    }
  }

  func requestJSON<T: Decodable & Sendable>(
    _ type: T.Type,
    path: String,
    method: AquariHTTPMethod = .get,
    headers: [String: String] = [:],
    body: Data? = nil,
    retryMode: AquariRetryMode = .auto
  ) async throws -> T {
    let (data, _) = try await requestData(
      path: path, method: method, headers: headers, body: body, retryMode: retryMode)
    return try decodeJSON(type, from: data, context: "Aquari API response")
  }

  func requestJSON<T: Decodable & Sendable>(
    _ type: T.Type,
    url: URL,
    method: AquariHTTPMethod = .get,
    headers: [String: String] = [:],
    body: Data? = nil,
    retryMode: AquariRetryMode = .auto
  ) async throws -> T {
    let (data, _) = try await requestData(
      url: url, method: method, headers: headers, body: body, retryMode: retryMode)
    return try decodeJSON(type, from: data, context: "Aquari OAuth response")
  }
}

func decodeJSON<T: Decodable>(_ type: T.Type, from data: Data, context: String) throws -> T {
  guard !data.isEmpty else {
    throw AquariError.invalidResponse("\(context) was empty.")
  }
  do {
    return try JSONDecoder().decode(type, from: data)
  } catch {
    throw AquariError.invalidResponse("\(context) was malformed.")
  }
}

private func isRetryable(method: AquariHTTPMethod, mode: AquariRetryMode) -> Bool {
  switch mode {
  case .never: return false
  case .idempotent: return true
  case .auto: return method == .get || method == .head || method == .options
  }
}

private func isRetryableStatus(_ status: Int) -> Bool {
  status == 429 || status == 502 || status == 503 || status == 504
}

/// Parses an HTTP Retry-After value and returns the retry delay when the value is valid.
public func parseRetryAfter(_ value: String?, now: Date = Date()) -> TimeInterval? {
  guard let value else { return nil }
  let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
  if !normalized.isEmpty, normalized.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) {
    return min(TimeInterval(normalized) ?? 9_007_199_254, 9_007_199_254)
  }
  if let date = HTTPDate.parse(normalized, now: now) {
    return max(0, date.timeIntervalSince(now))
  }
  return nil
}

private func retryDelay(response: HTTPURLResponse, attempt: Int) -> TimeInterval {
  parseRetryAfter(response.value(forHTTPHeaderField: "Retry-After"))
    ?? backoffDelay(attempt: attempt)
}

private func backoffDelay(attempt: Int) -> TimeInterval {
  let base = 0.25 * pow(2, Double(attempt))
  return base * Double.random(in: 0.5...1.0)
}

private func sleep(_ interval: TimeInterval) async throws {
  guard interval > 0 else { return }
  let nanoseconds = UInt64((interval * 1_000_000_000).rounded(.up))
  try await Task<Never, Never>.sleep(nanoseconds: nanoseconds)
}

private func parseAPIError(data: Data, response: HTTPURLResponse) -> AquariAPIError {
  var code: String?
  var message: String?
  var details: [String: [String]]?

  if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
    let error = object["error"] as? [String: Any]
  {
    code = error["code"] as? String
    message = error["message"] as? String
    if let rawDetails = error["details"] as? [String: Any] {
      var parsed: [String: [String]] = [:]
      for (key, value) in rawDetails {
        if let values = value as? [String] { parsed[key] = values }
      }
      details = parsed.isEmpty ? nil : parsed
    }
  }

  let status = response.statusCode
  let kind: AquariAPIErrorKind
  if code == "RateLimitExceeded" || status == 429 {
    kind = .rateLimit
  } else if code == "QuotaExceeded" {
    kind = .quota
  } else if code == "ValidationFailed" || status == 400 {
    kind = .validation
  } else if code == "Unauthorized" || status == 401 {
    kind = .authentication
  } else if code == "Forbidden" || status == 403 {
    kind = .authorization
  } else if status == 404 {
    kind = .notFound
  } else if code == "Conflict" || status == 409 {
    kind = .conflict
  } else {
    kind = .generic
  }

  let retryAfter = parseRetryAfter(response.value(forHTTPHeaderField: "Retry-After"))
  let quota =
    kind == .quota
    ? AquariQuotaMetadata(
      resource: first(details, "resource"),
      scopeType: first(details, "scopeType"),
      scopeID: first(details, "scopeId"),
      current: number(details, "current"),
      requested: number(details, "requested"),
      limit: number(details, "limit"),
      allowance: number(details, "allowance"),
      grace: number(details, "grace"),
      periodFrom: isoDate(first(details, "periodFrom")),
      periodTo: isoDate(first(details, "periodTo")),
      enforcement: first(details, "enforcement")
    ) : nil

  return AquariAPIError(
    kind: kind,
    status: status,
    code: code,
    message: message ?? HTTPURLResponse.localizedString(forStatusCode: status),
    details: details,
    retryAfter: retryAfter,
    quota: quota
  )
}

private func first(_ details: [String: [String]]?, _ key: String) -> String? {
  details?[key]?.first
}
private func number(_ details: [String: [String]]?, _ key: String) -> Double? {
  first(details, key).flatMap(Double.init)
}
private func isoDate(_ value: String?) -> Date? { value.flatMap(parseISO8601Date) }

enum HTTPDate {
  static func parse(_ value: String, now: Date) -> Date? {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.isLenient = false
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = formatter.timeZone
    formatter.twoDigitStartDate = calendar.date(
      from: DateComponents(
        year: calendar.component(.year, from: now) - 49, month: 1, day: 1))
    func normalized(_ text: String) -> String {
      text.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ").lowercased()
    }
    for format in [
      "EEE',' dd MMM yyyy HH':'mm':'ss z", "EEEE',' dd-MMM-yy HH':'mm':'ss z",
      "EEE MMM d HH':'mm':'ss yyyy",
    ] {
      formatter.dateFormat = format
      if let date = formatter.date(from: value),
        normalized(formatter.string(from: date)) == normalized(value)
      {
        return date
      }
    }
    return nil
  }
}
