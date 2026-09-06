#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use paccel::engine::QuicConnectionTracker;

// Drives the connection tracker as a state machine rather than feeding it one
// packet, because its bugs live in the indices rather than in any single
// parse. Tuples and connection IDs both point at connections, and every
// operation below can invalidate one without the other: a migration binds a
// second tuple, RETIRE_CONNECTION_ID drops an id, remove_flow drops a tuple,
// and expiry drops whole connections. The invariant checked after each step is
// that no index outlives what it points at, which is what stops a lookup
// returning another connection's packet numbers.
fuzz_target!(|data: &[u8]| {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    const MAX_CONNECTIONS: usize = 32;

    let mut tracker = QuicConnectionTracker::new().with_max_flows(MAX_CONNECTIONS);
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
                    tracker.observe_new_connection_id(id, u64::from(len_byte), cid, u64::from(op));
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
                    tracker.observe_retire_connection_id(id, u64::from(len_byte));
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
