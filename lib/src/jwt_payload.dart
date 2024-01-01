/// Decoded JWT payload with typed claim access.
///
/// ```dart
/// final payload = JwtDecoder.decode(token);
/// print(payload.subject);    // 'user-123'
/// print(payload.expiration); // DateTime(...)
/// ```
class JwtPayload {
  /// The raw claims map.
  final Map<String, dynamic> claims;

  /// Create a payload from a claims map.
  const JwtPayload(this.claims);

  /// The `sub` (subject) claim.
  String? get subject => claims['sub'] as String?;

  /// The `iss` (issuer) claim.
  String? get issuer => claims['iss'] as String?;

  /// The `aud` (audience) claim.
  String? get audience => claims['aud'] as String?;

  /// The `iat` (issued at) claim as a [DateTime].
  DateTime? get issuedAt {
    final iat = claims['iat'];
    if (iat is int) return DateTime.fromMillisecondsSinceEpoch(iat * 1000, isUtc: true);
    return null;
  }

  /// The `exp` (expiration) claim as a [DateTime].
  DateTime? get expiration {
    final exp = claims['exp'];
    if (exp is int) return DateTime.fromMillisecondsSinceEpoch(exp * 1000, isUtc: true);
    return null;
  }

  /// The `nbf` (not before) claim as a [DateTime].
  DateTime? get notBefore {
    final nbf = claims['nbf'];
    if (nbf is int) return DateTime.fromMillisecondsSinceEpoch(nbf * 1000, isUtc: true);
    return null;
  }

  /// Get a custom claim by [key], cast to type [T].
  ///
  /// Returns `null` if the claim doesn't exist or can't be cast.
  T? claim<T>(String key) {
    final value = claims[key];
    if (value is T) return value;
    return null;
  }

  @override
  String toString() => 'JwtPayload($claims)';
}
