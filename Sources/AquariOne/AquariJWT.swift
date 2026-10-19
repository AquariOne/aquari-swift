import Foundation

#if canImport(Security)
  import Security
#endif

struct AquariJWKSet: Decodable, Sendable { let keys: [AquariRSAJWK] }
struct AquariRSAJWK: Decodable, Sendable {
  let kty: String
  let kid: String?
  let use: String?
  let alg: String?
  let n: String
  let e: String
}

protocol AquariRS256SignatureVerifying: Sendable {
  func verify(message: Data, signature: Data, key: AquariRSAJWK) throws -> Bool
}

struct AquariDefaultRS256SignatureVerifier: AquariRS256SignatureVerifying {
  func verify(message: Data, signature: Data, key: AquariRSAJWK) throws -> Bool {
    #if canImport(Security)
      guard key.kty == "RSA", let modulus = base64URLDecode(key.n),
        let exponent = base64URLDecode(key.e)
      else { return false }
      let der = rsaPublicKeyDER(modulus: modulus, exponent: exponent)
      let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits: modulus.count * 8,
      ]
      var error: Unmanaged<CFError>?
      guard let secKey = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error)
      else { return false }
      return SecKeyVerifySignature(
        secKey, .rsaSignatureMessagePKCS1v15SHA256, message as CFData, signature as CFData, &error)
    #else
      throw AquariError.platformUnsupported(
        "RS256 verification requires Apple Security.framework on this platform.")
    #endif
  }
}

struct AquariJWTValidator: Sendable {
  let transport: AquariHTTPTransport
  let signatureVerifier: any AquariRS256SignatureVerifying

  func validate(
    idToken: String, discovery: AquariOIDCDiscovery, clientID: String, expectedNonce: String?
  ) async throws -> AquariIdentity {
    let parts = idToken.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3,
      let headerData = base64URLDecode(String(parts[0])),
      let payloadData = base64URLDecode(String(parts[1])),
      let signature = base64URLDecode(String(parts[2])),
      let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
      let payload = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any],
      header["alg"] as? String == "RS256",
      let kid = header["kid"] as? String, !kid.isEmpty
    else {
      throw invalidIDToken(
        "Aquari returned an ID token that is malformed or uses an unsupported algorithm.")
    }

    let jwks = try await transport.requestJSON(AquariJWKSet.self, url: discovery.jwksURI)
    guard
      let key = jwks.keys.first(where: {
        $0.kty == "RSA" && $0.kid == kid && ($0.alg == nil || $0.alg == "RS256")
      }),
      try signatureVerifier.verify(
        message: Data("\(parts[0]).\(parts[1])".utf8), signature: signature, key: key)
    else {
      throw invalidIDToken("Aquari returned an ID token that failed cryptographic validation.")
    }

    guard let issuer = payload["iss"] as? String, issuer == discovery.issuer else {
      throw invalidIDToken("Aquari ID token issuer is invalid.")
    }
    let audiences: [String]
    if let audience = payload["aud"] as? String {
      audiences = [audience]
    } else if let values = payload["aud"] as? [String] {
      audiences = values
    } else {
      throw invalidIDToken("Aquari ID token audience is invalid.")
    }
    guard audiences.contains(clientID) else {
      throw invalidIDToken("Aquari ID token audience does not include this client.")
    }
    if audiences.count > 1 {
      guard payload["azp"] as? String == clientID else {
        throw invalidIDToken(
          "Aquari ID token with multiple audiences must identify this client as the authorized party."
        )
      }
    }

    let now = Date().timeIntervalSince1970
    guard let exp = numberClaim(payload["exp"]), exp > now - 60 else {
      throw invalidIDToken("Aquari ID token is expired or missing expiration.")
    }
    guard let iat = numberClaim(payload["iat"]), iat <= now + 60 else {
      throw invalidIDToken("Aquari ID token issued-at claim is invalid.")
    }
    if let nbf = numberClaim(payload["nbf"]), nbf > now + 60 {
      throw invalidIDToken("Aquari ID token is not valid yet.")
    }
    if let expectedNonce {
      guard payload["nonce"] as? String == expectedNonce else {
        throw invalidIDToken("Aquari ID token nonce does not match the authorization transaction.")
      }
    }

    return try identity(from: payload)
  }
}

func identity(from payload: [String: Any]) throws -> AquariIdentity {
  guard let subject = payload["sub"] as? String, !subject.isEmpty else {
    throw invalidIDToken("Aquari identity is missing a valid subject claim.")
  }
  func optionalString(_ key: String) throws -> String? {
    guard let value = payload[key] else { return nil }
    guard let string = value as? String, !string.isEmpty else {
      throw invalidIDToken("Aquari identity claim '\(key)' is invalid.")
    }
    return string
  }
  func optionalBool(_ key: String) throws -> Bool? {
    guard let value = payload[key] else { return nil }
    guard let bool = value as? Bool else {
      throw invalidIDToken("Aquari identity claim '\(key)' is invalid.")
    }
    return bool
  }
  return AquariIdentity(
    subject: subject,
    handle: try optionalString("preferred_username"),
    canonicalHandle: try optionalString("https://aquari.one/claims/canonical_handle"),
    verifiedHandle: try optionalString("https://aquari.one/claims/verified_handle"),
    name: try optionalString("name"),
    pictureURL: try optionalString("picture"),
    email: try optionalString("email"),
    emailVerified: try optionalBool("email_verified")
  )
}

private func numberClaim(_ value: Any?) -> Double? {
  if value is Bool { return nil }
  if let number = value as? NSNumber { return number.doubleValue }
  if let number = value as? Double { return number }
  if let number = value as? Int { return Double(number) }
  return nil
}

private func invalidIDToken(_ message: String) -> AquariError {
  .oauth(AquariOAuthError(code: "invalid_id_token", message: message))
}

#if canImport(Security)
  private func rsaPublicKeyDER(modulus: Data, exponent: Data) -> Data {
    derSequence(derInteger(modulus) + derInteger(exponent))
  }
  private func derInteger(_ data: Data) -> Data {
    var value = data
    while value.count > 1 && value.first == 0
      && (value[value.index(after: value.startIndex)] & 0x80) == 0
    { value.removeFirst() }
    if let first = value.first, first & 0x80 != 0 { value.insert(0, at: value.startIndex) }
    return Data([0x02]) + derLength(value.count) + value
  }
  private func derSequence(_ data: Data) -> Data { Data([0x30]) + derLength(data.count) + data }
  private func derLength(_ count: Int) -> Data {
    if count < 128 { return Data([UInt8(count)]) }
    var value = count
    var bytes: [UInt8] = []
    while value > 0 {
      bytes.insert(UInt8(value & 0xff), at: 0)
      value >>= 8
    }
    return Data([0x80 | UInt8(bytes.count)] + bytes)
  }
#endif
