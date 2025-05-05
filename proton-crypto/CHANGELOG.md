# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2024-00-00

## [0.4.15] - 2025-05-05

### Changed

- Update `gopenpgp-sys` to 0.2.17.

## [0.4.14] - 2025-03-24

### Changed

- Update `gopenpgp-sys` to 0.2.16.
  
## [0.4.13] - 2025-03-06

### Changed

- Update `gopenpgp-sys` to 0.2.15.

## [0.4.12] - 2025-01-17

### Changed

- Update `gopenpgp-sys` to 0.2.14.
  
## [0.4.11] - 2024-12-13

### Changed

- Update `gopenpgp-sys` to 0.2.13.

## [0.4.10] - 2024-11-22

### Changed

- Make `SessionKeyAlgorithm` serializable.

## [0.4.9] - 2024-11-19

### Changed

- Update `gopenpgp-sys` to 0.2.12.

## [0.4.8] - 2024-10-22

### Changed

- Update `gopenpgp-sys` to 0.2.11.

## [0.4.7] - 2024-10-02

### Added

- `SRPProvider` allows to generate a client verifier for registration.
- Method to extract key password from the mailbox hashed password type.

### Changed

- Update `proton-srp` to 0.6.1.
- Update `gopenpgp-sys` to 0.2.10.

## [0.4.6] - 2024-09-11

### Changed

- Update `gopenpgp-sys` to 0.2.9.
- Update `proton-srp` to 0.5.1.

## [0.4.5] - 2024-08-13

### Bugfixes

- ET-231: Add `Clone` and `Sync` to `CryptoError` (#98)

## [0.4.4] - 2024-07-31

### Added

- ET-231: Implement `Clone` for `VerificationError` enum (#96)

## [0.4.3] - 2024-07-22

### Added

- Implement `AsPublicKeyRef` on reference on implementing type (#82)
  
### Changed

- Refactor `SessionKeyAlgorithm` type (#86)

## [0.4.2] - 2024-06-26


