# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2025-00-00

- `facet` feature flag to derive Facet macro on externaly used new types.

## [0.7.0] - 2025-09-02

### Added

- Feature flag `gopgp`, indicating usage of the Go PGP backend (enabled by default).
- Function `provider_version()` on the PGP provider to print the PGP library backend version.
- Explicit functions to access the Go PGP provider behind the feature flag: `new_go_pgp_provider()` and `new_go_pgp_provider_async()`.

### Changed

- Internal refactoring to prepare support for multiple backends.
- `OpenPGPKeyID` now only implements the `From<u64>` trait.
- Macro `lowercase_string_id` now only implements the `From<String>` trait.
- Made the following types in the CryptoAPI public: `RawDetachedSignature`, `RawEncryptedMessage`, and `PGPKeyPackets`.
- Update `gopenpgp-sys` to 0.3.2.

## [0.6.0] - 2025-06-30

### Added

- Encrypt an OpenPGP message with a passphrase using the `PGPProvider`.

## [0.5.1] - 2025-06-18

### Changed

- Update `gopenpgp-sys` to 0.3.1.


## [0.5.0] - 2025-05-26

### Changed

- Update `gopenpgp-sys` to 0.3.0. Adds support for the final OpenPGP PQC draft.

## [0.4.16] - 2025-05-05

### Changed

- Update `gopenpgp-sys` to 0.2.18.

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


