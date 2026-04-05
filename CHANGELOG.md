## [0.2.0] - 2026-04-04

### Added
- `JwtDecoder.decodeHeader()` for extracting JWT header claims
- `JwtDecoder.algorithm()` convenience method for the `alg` claim

## [0.1.1] - 2026-04-03

### Fixed
- Primary barrel file now matches package name for pub.dev validation

## [0.1.0] - 2026-04-03

### Added

- `JwtDecoder.decode` for parsing JWT tokens
- `JwtPayload` with typed claim access (subject, issuedAt, expiration, issuer)
- `JwtDecoder.isExpired` with clock skew tolerance
- `JwtDecoder.timeToExpiry` for remaining validity
- Custom claim access via `claim<T>()`
- Zero external dependencies
