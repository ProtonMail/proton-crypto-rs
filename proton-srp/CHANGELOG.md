# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2024-00-00

### Added
- Add SRP API with a custom random number generator. 

### Changed
- pgp bumped to `0.17.0`.

## 0.7.1 2025-09-02

### Changed
- bcrypt bumped to `0.17.1`.
- pgp bumped to `0.16.0`.

## 0.7.0 2025-05-05

### Added
- Add SRP server support.

## 0.6.1 2024-10-01

### Added
- Add `MailboxHashedPassword` methods to extract bcrypt prefix and hashed password.

### Changed
- bcrypt bumped to `15.1`.

## 0.6.0 2024-09-30

### Changed
 - Renamed `SRPAuth::generate_random_verifier` to `SRPAuth::generate_verifier`
 - Renamed `SRPAuth::generate_random_verifier_with_pgp` to `SRPAuth::generate_verifier_with_pgp`
 - Refactored project layout with improved documentation

## 0.5.1 2024-08-30

### Fixed
 - Make `pgpinternal` feature flag additive. Forgot to adapt generate random verifier.

## 0.5.0 2024-08-29

### Changed
 - Make `pgpinternal` feature flag additive.

## 0.4.2 2024-08-14

### Changed
 - Update optional rpgp dependency to 13.1

## 0.3.1 2024-04-26

### Changed
 - Enforce that the generic verify error is Send.
 - Make MailboxHashError public

## 0.3.0 2024-04-10

### Added
 - Refactored API to be similar to the js/go production implementations
 - Uses constant-time big integers (security benefit)
 - Improve performance
 - Clear sensitive information from memory
 - Handle b64 encoding/decoding
 - (feature flag pgpinternal disabled) OpenPGP dependency for modulus verification is outsourced to a trait
 - (feature flag pgpinternal enabled) Modulus verification is performed internally via rPGP
 - More tests
 - Add mailbox password hash function

## 0.2.1 2024-04-09

### Added
 -  Move registry to shared repo
 -  Move gitlab-ci to shared repo