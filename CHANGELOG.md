# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-04-17

### Added
- `JwtPayload.audienceList` getter for RFC 7519 array audience support
- `JwtDecoder.isNotYetValid()` for checking the `nbf` (not before) claim

## [0.4.0] - 2026-04-11

### Added
- `JwtDecoder.tryDecode()` for null-safe payload decoding
- `JwtDecoder.tryDecodeHeader()` for null-safe header decoding
- `JwtPayload.jwtId` getter for the `jti` (JWT ID) claim

## [0.3.0] - 2026-04-05

### Added
- `JwtDecoder.isValid()` for checking JWT structure without decoding or verifying signatures

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
