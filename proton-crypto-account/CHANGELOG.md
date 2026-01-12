# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2025-00-00

## [0.13.0] - 2026-01-08

### Changed

- Ensure all errors are Send + 'static
- Update `proton-crypto` to 0.8.0.

## Added 

- `facet` feature flag to derive Facet macro on API types.

## [0.12.3] - 2025-11-07

### Changed

- Update `proton-crypto` to 0.7.1.

## [0.12.2] - 2025-09-02

### Changed

- Update `proton-crypto` to 0.7.0.

## [0.12.1] - 2025-08-29

### Changed

- A PQC user only signs with the legacy primary key instead of both primary keys for now.

## [0.12.0] - 2025-07-02

### Changed

- Update `RecipientPublicKeyModel::from_public_keys_at_time` has an additional argument `prefer_v6`.

### Fixed

- The `RecipientPublicKeyModel` now prioritizes public keys correctly.

## [0.11.2] - 2025-06-30

### Changed

- Update `proton-crypto` to 0.6.0.

## [0.11.1] - 2025-06-18

### Changed

- Update `proton-crypto` to 0.5.1.

## [0.11.0] - 2025-05-26

### Changed

- Update `proton-crypto` to 0.5.0.

## [0.10.2] - 2025-05-15

### Changed

- Update `proton-crypto` to 0.4.16.

## [0.10.1] - 2025-05-05

### Changed

- Update `proton-crypto` to 0.4.15.

## [0.10.0] - 2025-03-26

### Changed

- `export_public_key` returns a tuple with the key fingerprint instead of just the armored key.

## [0.9.1] - 2025-03-24

### Changed

- Update `proton-crypto` to 0.4.14.

## [0.9.0] - 2025-03-06

### Added

- Add `PGPDeviceKey` keys for device-local OpenPGP keys.

### Changed

- Renamed `AddressKeyExportError` to generic `KeySerializationError`.
- Update `proton-crypto` to 0.4.13.

## [0.8.3] - 2025-02-01

### Fixed

- Strip trailing spaces in sign/verify contact card

## [0.8.2] - 2025-01-17

### Changed

- Update `proton-crypto` to 0.4.12.

## [0.8.1] - 2025-01-06

### Added 

- Add `export_public_key` method  on unlocked address key types.
  
## [0.8.0] - 2024-12-17

### Added 

- Make API PQC ready with OpenPGP v6 primary address key support.
- Introduce a `primary_for_mail()` method on address keys to get the encryption/signing key with v6 support.
- Introduce a `PrimaryUnlockedAddressKey` type for a primary address key, which is potentially v6.

### Changed

- Rename `primary()` on unlocked address keys to `primary_default()`
- SKL generation now takes `UnlockedAddressKeys` as input.

## [0.7.4] - 2024-12-13

### Changed

- Update rusqlite to `0.32.1`

## [0.7.3] - 2024-11-26

### Changed

- `ContactCardType` must derive `Serialize_repr` and `Deserialize_repr`.

## [0.7.2] - 2024-11-22

### Changed

- Update `proton-crypto` to 0.4.9.

## [0.7.1] - 2024-11-19

### Changed

- Update `proton-crypto` to 0.4.9.

## [0.7.0] - 2024-10-22

### Changed

- Replaced `UnlockedUserKeys`, `UnlockedAddressKeys` type aliases with actual structs providing helper methods. 
- Update `proton-crypto` to 0.4.8.

## [0.6.3] - 2024-10-02

### Changed

- Adapt key secret extraction to new `SRPProvider` version.
- Update `proton-crypto` to 0.4.7.

### Fixed

-  Fix encryption preferences `encrypt` setting for external users with API keys.

## [0.6.2] - 2024-09-11

### Dependencies

- update proton-crypto to 0.4.6


## [0.6.1] - 2024-08-26

### Added 

- `RecipientPublicKeyModel`: Serves as an intermediary type that mirrors vCard content alongside public key information retrieved from the API. This model facilitates the creation of encryption and send preferences.
  
### Changed

- Replace `proton-sql` with `rusqlite`.

## [0.6.0] - 2024-08-13

### Changed

- Add ToSql and FromSql traits to ContactCardType.  Introduce new, "sql" feature flag for crate and move all ToSql/FromSql implementations to be behind the flag (#101)

### Dependencies

- update proton-crypto to 0.4.5

## [0.5.1] - 2024-07-31

### Dependencies

- update proton-crypto to 0.4.4

## [0.5.0] - 2024-07-30

### Changed

- Changed `AttachmentDecryption` to accepts options as `Option<&T>`.

## [0.4.2] - 2024-07-23

### Added

- Add rusqlite ToSql and FromSql traits to the string_id! macro (#92)

## [0.4.1] - 2024-07-22

### Added

- ET-781: encrypt and sign vcards (#81)
- Change locking variant of an existing key (#80)
- Generate signed key lists (SKL) (#82)

## [0.4.0] - 2024-06-26


