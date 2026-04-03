# philiprehberger_jwt_decoder

[![Tests](https://github.com/philiprehberger/dart-jwt-decoder/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/dart-jwt-decoder/actions/workflows/ci.yml)
[![pub package](https://img.shields.io/pub/v/philiprehberger_jwt_decoder.svg)](https://pub.dev/packages/philiprehberger_jwt_decoder)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/dart-jwt-decoder)](https://github.com/philiprehberger/dart-jwt-decoder/commits/main)

Lightweight JWT token decoder with typed claim access and expiration checking

## Requirements

- Dart >= 3.6

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  philiprehberger_jwt_decoder: ^0.1.0
```

Then run:

```bash
dart pub get
```

## Usage

```dart
import 'package:philiprehberger_jwt_decoder/jwt_decoder.dart';

final payload = JwtDecoder.decode(token);
print(payload.subject);    // user-123
print(payload.expiration); // 2026-04-04 12:00:00.000
```

### Check Expiration

```dart
if (JwtDecoder.isExpired(token)) {
  print('Token has expired');
}

final remaining = JwtDecoder.timeToExpiry(token);
print('Expires in ${remaining?.inMinutes} minutes');
```

### Clock Skew Tolerance

```dart
JwtDecoder.isExpired(token, clockSkew: Duration(seconds: 30));
```

### Custom Claims

```dart
final payload = JwtDecoder.decode(token);
final role = payload.claim<String>('role');     // 'admin'
final level = payload.claim<int>('level');      // 5
```

## API

| Method | Description |
|--------|-------------|
| `JwtDecoder.decode(token)` | Decode a JWT and return its payload |
| `JwtDecoder.isExpired(token, {clockSkew})` | Check if a token has expired |
| `JwtDecoder.timeToExpiry(token)` | Get remaining time until expiration |
| `JwtPayload.subject` | The `sub` claim |
| `JwtPayload.issuedAt` | The `iat` claim as DateTime |
| `JwtPayload.expiration` | The `exp` claim as DateTime |
| `JwtPayload.issuer` | The `iss` claim |
| `JwtPayload.claim<T>(key)` | Get any custom claim by key |

## Development

```bash
dart pub get
dart analyze --fatal-infos
dart test
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/dart-jwt-decoder)

🐛 [Report issues](https://github.com/philiprehberger/dart-jwt-decoder/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/dart-jwt-decoder/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
