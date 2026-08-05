Most `.pcap`/`.pcapng`/`.cap` files in this directory are third-party test captures
redistributed from the Wireshark project (GPLv2), used here only as local test data —
see the "Test fixture provenance" table in the repository root `README.md` for the
exact source of each file. A few are hand-built (via `scapy`) or of unrecorded origin,
also noted in that table.

These files are not part of the `paccel` crate: `tests/pcaps/` is excluded from the
published package (`Cargo.toml`'s `exclude`), so none of this ships to consumers of
the crate. The crate itself, everything under `src/`, is original and licensed
Apache-2.0 per the repository root `LICENSE`.
