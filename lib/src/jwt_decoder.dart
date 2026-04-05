import 'dart:convert';

import 'jwt_payload.dart';

/// Decodes JWT tokens without signature verification.
///
/// This is intended for client-side token inspection (reading claims,
/// checking expiration). It does NOT verify signatures — that should
/// be done server-side.
///
/// ```dart
/// final payload = JwtDecoder.decode(token);
/// print(payload.subject);
/// ```
class JwtDecoder {
  JwtDecoder._();

  /// Decode a JWT [token] and return its payload.
  ///
  /// Throws [FormatException] if the token is malformed.
  static JwtPayload decode(String token) {
    final parts = token.split('.');
    if (parts.length != 3) {
      throw FormatException('Invalid JWT: expected 3 parts, got ${parts.length}');
    }

    final payload = _decodeBase64(parts[1]);
    final json = jsonDecode(payload);

    if (json is! Map<String, dynamic>) {
      throw const FormatException('Invalid JWT: payload is not a JSON object');
    }

    return JwtPayload(json);
  }

  /// Check if a JWT [token] has expired.
  ///
  /// Returns `true` if the token has no `exp` claim.
  /// Optionally provide [clockSkew] to allow for clock drift.
  static bool isExpired(String token, {Duration clockSkew = Duration.zero}) {
    final payload = decode(token);
    final exp = payload.expiration;
    if (exp == null) return true;
    return DateTime.now().toUtc().isAfter(exp.add(clockSkew));
  }

  /// Get the remaining time until the token expires.
  ///
  /// Returns `null` if the token has no `exp` claim.
  /// Returns a negative duration if the token has already expired.
  static Duration? timeToExpiry(String token) {
    final payload = decode(token);
    final exp = payload.expiration;
    if (exp == null) return null;
    return exp.difference(DateTime.now().toUtc());
  }

  /// Decodes the JWT header and returns the claims map.
  ///
  /// Throws [FormatException] if the token is malformed.
  static Map<String, dynamic> decodeHeader(String token) {
    final parts = token.split('.');
    if (parts.length != 3) {
      throw FormatException(
          'Invalid JWT: expected 3 parts, got ${parts.length}');
    }

    final header = _decodeBase64(parts[0]);
    final json = jsonDecode(header);

    if (json is! Map<String, dynamic>) {
      throw const FormatException('Invalid JWT: header is not a JSON object');
    }

    return json;
  }

  /// Returns the algorithm from the JWT header (the `alg` claim).
  ///
  /// Returns `null` if the `alg` claim is not present.
  static String? algorithm(String token) {
    final header = decodeHeader(token);
    return header['alg'] as String?;
  }

  static String _decodeBase64(String input) {
    // Add padding if necessary
    var normalized = input.replaceAll('-', '+').replaceAll('_', '/');
    switch (normalized.length % 4) {
      case 2:
        normalized += '==';
      case 3:
        normalized += '=';
    }
    return utf8.decode(base64Decode(normalized));
  }
}
