#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use paccel::engine::{Endpoint, QuicConnectionTracker};

// Drives the tracker as a state machine: the bugs are in the indices, not in
// any one parse. After every step, no index may outlive what it points at.
//
// Both endpoints issue connection IDs, because each numbers its own from zero
// and a one-sided driver cannot reach the collision between the two pools.
fuzz_target!(|data: &[u8]| {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    const MAX_CONNECTIONS: usize = 32;
    const MAX_TUPLES: usize = 64;
    const MAX_TUPLES_PER_CONNECTION: usize = 4;
    const MAX_CIDS: usize = 64;
    const MAX_CIDS_PER_POOL: usize = 4;

    let mut tracker = QuicConnectionTracker::new()
        .with_max_flows(MAX_CONNECTIONS)
        .with_max_tuples(MAX_TUPLES, MAX_TUPLES_PER_CONNECTION)
        .with_max_cids(MAX_CIDS)
        .with_max_cids_per_pool(MAX_CIDS_PER_POOL);
    let mut cursor = data;
    let mut announced: Vec<Vec<u8>> = Vec::new();

    while let Some((&op, rest)) = cursor.split_first() {
        cursor = rest;
        let Some((&port_byte, rest)) = cursor.split_first() else {
            break;
        };
        cursor = rest;
        let Some((&len_byte, rest)) = cursor.split_first() else {
            break;
        };
        cursor = rest;

        let port = 40_000u16.wrapping_add(u16::from(port_byte));
        let take = usize::from(len_byte % 24).min(cursor.len());
        let (cid, rest) = cursor.split_at(take);
        cursor = rest;
        let now = u64::from(port_byte);
        // Alternate which end issues, so both sequence spaces are exercised.
        let issuer = if op & 0x40 == 0 {
            Endpoint::new(src, port)
        } else {
            Endpoint::new(dst, 443)
        };

        match op % 6 {
            0 => {
                tracker.observe_long_header_at(src, port, dst, 443, cid, now);
                if !cid.is_empty() {
                    announced.push(cid.to_vec());
                }
            }
            1 => {
                tracker.observe_short_header_at(src, port, dst, 443, cid, now);
            }
            2 => {
                if let Some(id) = announced
                    .first()
                    .and_then(|first| tracker.connection_id_for_dcid(first))
                {
                    tracker.observe_new_connection_id(
                        id,
                        issuer,
                        u64::from(len_byte),
                        cid,
                        u64::from(op % 4),
                    );
                    if !cid.is_empty() && cid.len() <= 20 {
                        announced.push(cid.to_vec());
                    }
                }
            }
            3 => {
                if let Some(id) = announced
                    .first()
                    .and_then(|first| tracker.connection_id_for_dcid(first))
                {
                    tracker.observe_retire_connection_id(id, issuer, u64::from(len_byte));
                }
            }
            4 => {
                tracker.remove_flow(src, port, dst, 443);
            }
            _ => {
                tracker.expire_before(now);
            }
        }

        let stats = tracker.stats();
        assert!(
            stats.active_connections <= MAX_CONNECTIONS,
            "{} connections past the {MAX_CONNECTIONS} cap",
            stats.active_connections
        );
        assert!(
            stats.active_connections <= stats.active_tuples,
            "{} connections hold only {} addresses between them",
            stats.active_connections,
            stats.active_tuples
        );
        // Migration binds tuples and NEW_CONNECTION_ID adds ids without adding
        // connections, so each index needs its own bound.
        assert!(
            stats.active_tuples <= MAX_TUPLES,
            "{} address pairs past the {MAX_TUPLES} cap",
            stats.active_tuples
        );
        assert!(
            stats.active_cids <= MAX_CIDS,
            "{} connection ids past the {MAX_CIDS} cap",
            stats.active_cids
        );
        let mut distinct: Vec<&[u8]> = announced.iter().map(Vec::as_slice).collect();
        distinct.sort_unstable();
        distinct.dedup();
        let held: usize = distinct
            .iter()
            .map(|cid| tracker.connections_for_dcid(cid).len())
            .sum();
        assert_eq!(
            held, stats.active_cids,
            "{held} bindings held but {} counted",
            stats.active_cids
        );
        assert_eq!(
            distinct
                .iter()
                .filter(|cid| !tracker.connections_for_dcid(cid).is_empty())
                .count(),
            stats.distinct_cids,
            "distinct ids disagree with the index"
        );

        for cid in &announced {
            if let Some(id) = tracker.connection_id_for_dcid(cid) {
                assert!(
                    !tracker.tuples_for_connection(id).is_empty(),
                    "an id resolved to a connection with no addresses"
                );
                assert!(
                    tracker.connection_for_dcid(cid).is_some(),
                    "an id resolved by one lookup and not the other"
                );
            }
        }
    }
});
