# Proton Cryptography Rust

Utility crates for cryptographic operations at Proton.
Not intended or vetted for general usage outside Proton.

## Crates

- **proton-crypto**: Core Proton cryptography library: generic Proton-specific OpenPGP and SRP API. Backends: GopenPGP (`gopgp`) or pure Rust (`rustpgp` via proton-rpgp).
- **proton-crypto-account**: Proton account cryptography (user keys, address keys, etc.) and key management; re-exports `proton-crypto`.
- **proton-rpgp**: Pure Rust OpenPGP wrapper on top of [rpgp](https://github.com/rpgp/rpgp) (used as optional backend in `proton-crypto`).
- **gopenpgp-sys**: Rust bindings to [GopenPGP](https://github.com/ProtonMail/gopenpgp).
- **proton-srp**: Pure Rust implementation of Proton’s Secure Remote Password (SRP) protocol.
- **proton-crypto-subtle**: Low-level primitives: AEAD, HKDF.
- **proton-device-verification**: Device verification for clients.

## Build

```bash
cargo build
```

The default `proton-crypto` backend is [GopenPGP](https://github.com/ProtonMail/gopenpgp) (`gopgp`), which requires [Go](https://go.dev/) to build `gopenpgp-sys`. For a pure Rust build, use:

```bash
cargo build --no-default-features -p proton-crypto -p proton-crypto-account --features rustpgp
```

## Contributions

We are not currently accepting external contributions via this GitHub repository. This open-source mirror is provided for transparency and reference.

## License

MIT. See [LICENSE](LICENSE).

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

