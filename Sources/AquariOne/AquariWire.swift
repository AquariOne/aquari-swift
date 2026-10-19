import Foundation

func parseISO8601Date(_ value: String) -> Date? {
  let formatter = ISO8601DateFormatter()
  formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
  if let date = formatter.date(from: value) { return date }
  formatter.formatOptions = [.withInternetDateTime]
  return formatter.date(from: value)
}

func requireISO8601(_ value: String, field: String) throws -> String {
  guard parseISO8601Date(value) != nil else {
    throw AquariError.invalidResponse("Aquari field '\(field)' must be an ISO-8601 timestamp.")
  }
  return value
}

func requireNonEmpty(_ value: String, field: String) throws -> String {
  guard !value.isEmpty, value == value.trimmingCharacters(in: .whitespacesAndNewlines) else {
    throw AquariError.invalidResponse(
      "Aquari field '\(field)' must be a non-empty normalized string.")
  }
  return value
}

func bearerHeaders(_ accessToken: String) throws -> [String: String] {
  guard !accessToken.isEmpty,
    accessToken == accessToken.trimmingCharacters(in: .whitespacesAndNewlines)
  else {
    throw AquariError.configuration(
      "Aquari access token must be non-empty without surrounding whitespace.")
  }
  return ["Authorization": "Bearer \(accessToken)"]
}

func encodePathSegment(_ value: String, label: String) throws -> String {
  guard !value.isEmpty, value == value.trimmingCharacters(in: .whitespacesAndNewlines) else {
    throw AquariError.configuration(
      "Aquari \(label) must be non-empty without surrounding whitespace.")
  }
  var allowed = CharacterSet.alphanumerics
  allowed.insert(charactersIn: "-._~")
  guard let encoded = value.addingPercentEncoding(withAllowedCharacters: allowed) else {
    throw AquariError.configuration("Aquari \(label) could not be encoded.")
  }
  return encoded
}
