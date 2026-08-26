Most protocol test data lives inline in `tests/pcap_integration.rs` as
paccel-authored synthetic frames, each verified against that protocol's
own parser source. The few files here are self-generated or of unrecorded
origin, not third-party — see the "Test fixture provenance" table in the
repository root `README.md`.

These files are not part of the `paccel` crate: `tests/pcaps/` is excluded from the
published package (`Cargo.toml`'s `exclude`), so none of this ships to consumers of
the crate. The crate itself, everything under `src/`, is original and licensed
Apache-2.0 per the repository root `LICENSE`.
