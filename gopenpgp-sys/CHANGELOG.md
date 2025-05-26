# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2025-00-00

## [0.3.0] - 2025-26-05

### Changed

- Update GopenPGP to `v3.3.0-proton`. Changes PQC to final draft, thus, breaking version upgrade.

## [0.2.18] - 2025-15-05

### Changed

- Fix typos `Sing` to `Sign`.
- Update `bindgen` to `0.71`.

## [0.2.17] - 2025-05-05

### Changed

- Update GopenPGP to `v3.2.1-proton`
- Remove `OwnedCStr::to_cstring`
- Simplify logic in `ext_buffer_write()`

## [0.2.16] - 2025-03-24

### Changed

- Update GopenPGP to `v3.1.3-proton`

## [0.2.15] - 2025-03-06

### Fixed

- Return complete hex KeyID 

## [0.2.14] - 2025-01-17

### Changed

- Update GopenPGP to `v3.1.2-proton`

## [0.2.13] - 2024-12-13

### Changed

- Update GopenPGP to `v3.1.0-proton.2`
- Fix gopenpgp-sys iOS build for go 1.23.x

## [0.2.12] - 2024-11-19

### Changed

- Update GopenPGP to `v3.0.0-proton`
- Make gopenpgp-sys iOS build more robust

## [0.2.11] - 2024-10-22

### Changed

- Update GopenPGP to `v3.0.0-beta.2-proton`

## [0.2.10] - 2024-10-02

### Changed

- Improved build script for GopenPGP.
- Move unit tests into a separate folder.
- Update `bindgen` to `0.70`.

## [0.2.9] - 2024-09-11

### Fixed

- Fix android build on mac os by adding sysroot ndk clang argument to bindgen (#110).

## [0.2.8] - 2024-07-22

### Fixed

- Allow to encrypt large content >1MB to bytes in non-streaming mode (#87)


## [0.2.7] - 2024-06-26


