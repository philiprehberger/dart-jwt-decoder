## [0.1.0] - 2026-04-03

### Added

- `JwtDecoder.decode` for parsing JWT tokens
- `JwtPayload` with typed claim access (subject, issuedAt, expiration, issuer)
- `JwtDecoder.isExpired` with clock skew tolerance
- `JwtDecoder.timeToExpiry` for remaining validity
- Custom claim access via `claim<T>()`
- Zero external dependencies
