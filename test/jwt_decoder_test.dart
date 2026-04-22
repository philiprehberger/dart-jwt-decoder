import 'dart:convert';

import 'package:philiprehberger_jwt_decoder/jwt_decoder.dart';
import 'package:test/test.dart';

String _createToken(Map<String, dynamic> payload) {
  final header = base64Url.encode(utf8.encode('{"alg":"HS256","typ":"JWT"}')).replaceAll('=', '');
  final body = base64Url.encode(utf8.encode(jsonEncode(payload))).replaceAll('=', '');
  return '$header.$body.fake-signature';
}

void main() {
  group('JwtDecoder', () {
    test('decodes a valid JWT', () {
      final token = _createToken({'sub': 'user-123', 'iss': 'test'});
      final payload = JwtDecoder.decode(token);
      expect(payload.subject, equals('user-123'));
      expect(payload.issuer, equals('test'));
    });

    test('reads expiration claim', () {
      final exp = DateTime.utc(2030, 1, 1).millisecondsSinceEpoch ~/ 1000;
      final token = _createToken({'exp': exp});
      final payload = JwtDecoder.decode(token);
      expect(payload.expiration, equals(DateTime.utc(2030, 1, 1)));
    });

    test('reads issuedAt claim', () {
      final iat = DateTime.utc(2026, 1, 1).millisecondsSinceEpoch ~/ 1000;
      final token = _createToken({'iat': iat});
      final payload = JwtDecoder.decode(token);
      expect(payload.issuedAt, equals(DateTime.utc(2026, 1, 1)));
    });

    test('isExpired returns true for expired token', () {
      final exp = DateTime.utc(2020, 1, 1).millisecondsSinceEpoch ~/ 1000;
      final token = _createToken({'exp': exp});
      expect(JwtDecoder.isExpired(token), isTrue);
    });

    test('isExpired returns false for valid token', () {
      final exp = DateTime.now().toUtc().add(Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000;
      final token = _createToken({'exp': exp});
      expect(JwtDecoder.isExpired(token), isFalse);
    });

    test('isExpired respects clock skew', () {
      // Token that expired 10 seconds ago
      final exp = DateTime.now().toUtc().subtract(Duration(seconds: 10)).millisecondsSinceEpoch ~/ 1000;
      final token = _createToken({'exp': exp});
      // Without skew: expired
      expect(JwtDecoder.isExpired(token), isTrue);
      // With 30s skew: not expired
      expect(JwtDecoder.isExpired(token, clockSkew: Duration(seconds: 30)), isFalse);
    });

    test('timeToExpiry returns positive duration for valid token', () {
      final exp = DateTime.now().toUtc().add(Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000;
      final token = _createToken({'exp': exp});
      final remaining = JwtDecoder.timeToExpiry(token);
      expect(remaining, isNotNull);
      expect(remaining!.inMinutes, greaterThanOrEqualTo(59));
    });

    test('timeToExpiry returns null when no exp claim', () {
      final token = _createToken({'sub': 'user'});
      expect(JwtDecoder.timeToExpiry(token), isNull);
    });

    test('custom claims are accessible', () {
      final token = _createToken({'role': 'admin', 'level': 5});
      final payload = JwtDecoder.decode(token);
      expect(payload.claim<String>('role'), equals('admin'));
      expect(payload.claim<int>('level'), equals(5));
    });

    test('missing custom claim returns null', () {
      final token = _createToken({'sub': 'user'});
      final payload = JwtDecoder.decode(token);
      expect(payload.claim<String>('missing'), isNull);
    });

    test('throws FormatException for malformed token', () {
      expect(() => JwtDecoder.decode('not-a-jwt'), throwsFormatException);
    });

    test('throws FormatException for token with wrong part count', () {
      expect(() => JwtDecoder.decode('a.b'), throwsFormatException);
      expect(() => JwtDecoder.decode('a.b.c.d'), throwsFormatException);
    });

    test('isExpired returns true when no exp claim', () {
      final token = _createToken({'sub': 'user'});
      expect(JwtDecoder.isExpired(token), isTrue);
    });

    test('tryDecode returns payload for valid token', () {
      final token = _createToken({'sub': 'user-123'});
      final payload = JwtDecoder.tryDecode(token);
      expect(payload, isNotNull);
      expect(payload!.subject, equals('user-123'));
    });

    test('tryDecode returns null for malformed token', () {
      expect(JwtDecoder.tryDecode('not-a-jwt'), isNull);
      expect(JwtDecoder.tryDecode('a.b'), isNull);
    });

    test('tryDecodeHeader returns header for valid token', () {
      final token =
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      final header = JwtDecoder.tryDecodeHeader(token);
      expect(header, isNotNull);
      expect(header!['alg'], 'HS256');
    });

    test('tryDecodeHeader returns null for malformed token', () {
      expect(JwtDecoder.tryDecodeHeader('not-a-jwt'), isNull);
    });
  });

  group('decodeHeader', () {
    test('extracts algorithm from header', () {
      // Standard JWT with {"alg":"HS256","typ":"JWT"} header
      final token =
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      final header = JwtDecoder.decodeHeader(token);
      expect(header['alg'], 'HS256');
      expect(header['typ'], 'JWT');
    });

    test('throws on malformed token', () {
      expect(() => JwtDecoder.decodeHeader('not-a-jwt'), throwsFormatException);
    });
  });

  group('algorithm', () {
    test('returns algorithm string', () {
      final token =
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      expect(JwtDecoder.algorithm(token), 'HS256');
    });

    test('returns null when alg is missing', () {
      // Header: {"typ":"JWT"} = eyJ0eXAiOiJKV1QifQ
      final token =
          'eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature';
      expect(JwtDecoder.algorithm(token), isNull);
    });
  });

  group('JwtPayload.jwtId', () {
    test('returns jti claim when present', () {
      final token = _createToken({'jti': 'abc-123'});
      final payload = JwtDecoder.decode(token);
      expect(payload.jwtId, equals('abc-123'));
    });

    test('returns null when jti is absent', () {
      final token = _createToken({'sub': 'user'});
      final payload = JwtDecoder.decode(token);
      expect(payload.jwtId, isNull);
    });
  });

  group('JwtPayload.audienceList', () {
    test('returns single-element list for string audience', () {
      final token = _createToken({'aud': 'my-app'});
      final payload = JwtDecoder.decode(token);
      expect(payload.audienceList, equals(['my-app']));
    });

    test('returns list for array audience', () {
      final token = _createToken({'aud': ['app-1', 'app-2']});
      final payload = JwtDecoder.decode(token);
      expect(payload.audienceList, equals(['app-1', 'app-2']));
    });

    test('returns empty list when no audience', () {
      final token = _createToken({'sub': 'user'});
      final payload = JwtDecoder.decode(token);
      expect(payload.audienceList, isEmpty);
    });
  });

  group('JwtDecoder.isNotYetValid', () {
    test('returns false when no nbf claim', () {
      final token = _createToken({'sub': 'user'});
      expect(JwtDecoder.isNotYetValid(token), isFalse);
    });

    test('returns true for future nbf', () {
      final future = DateTime.now().toUtc().add(Duration(hours: 1));
      final token = _createToken({
        'nbf': future.millisecondsSinceEpoch ~/ 1000,
      });
      expect(JwtDecoder.isNotYetValid(token), isTrue);
    });

    test('returns false for past nbf', () {
      final past = DateTime.now().toUtc().subtract(Duration(hours: 1));
      final token = _createToken({
        'nbf': past.millisecondsSinceEpoch ~/ 1000,
      });
      expect(JwtDecoder.isNotYetValid(token), isFalse);
    });

    test('respects clock skew', () {
      final slightlyFuture = DateTime.now().toUtc().add(Duration(seconds: 10));
      final token = _createToken({
        'nbf': slightlyFuture.millisecondsSinceEpoch ~/ 1000,
      });
      expect(JwtDecoder.isNotYetValid(token), isTrue);
      expect(
        JwtDecoder.isNotYetValid(token, clockSkew: Duration(seconds: 30)),
        isFalse,
      );
    });
  });
}
