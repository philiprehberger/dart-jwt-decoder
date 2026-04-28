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

  /// The `aud` (audience) claim as a list.
  ///
  /// Per RFC 7519, the `aud` claim may be a single string or an array.
  /// This getter always returns a list for uniform access.
  List<String> get audienceList {
    final aud = claims['aud'];
    if (aud is String) return [aud];
    if (aud is List) return aud.cast<String>();
    return [];
  }

  /// The `jti` (JWT ID) claim.
  String? get jwtId => claims['jti'] as String?;

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

  /// Get a custom claim by [key], cast to type [T], or [defaultValue] if
  /// the claim is absent or cannot be cast to [T].
  ///
  /// ```dart
  /// final role = payload.claimOr<String>('role', 'guest');
  /// final level = payload.claimOr<int>('level', 0);
  /// ```
  T claimOr<T>(String key, T defaultValue) {
    final value = claim<T>(key);
    return value ?? defaultValue;
  }

  /// Returns a map containing only the requested [keys] that are present
  /// in the payload.
  ///
  /// Missing keys are skipped (not inserted as `null`).
  ///
  /// ```dart
  /// final subset = payload.pickClaims(['sub', 'role', 'tenant']);
  /// ```
  Map<String, dynamic> pickClaims(List<String> keys) {
    final out = <String, dynamic>{};
    for (final k in keys) {
      if (claims.containsKey(k)) out[k] = claims[k];
    }
    return out;
  }

  @override
  String toString() => 'JwtPayload($claims)';
}
