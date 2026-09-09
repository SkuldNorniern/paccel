//! Opt-in TCP session tracking and streaming application-layer probing.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::engine::flow::{BiFlow, LastSeen, Timestamp};
use crate::engine::reassembly::TcpReassemblyStats;
use crate::engine::{BuiltinPacketParser, ParsedPacket, TcpStreamReassembler, TransportSegment};
use crate::layer::ProbeResult;
use crate::layer::application::bgp::{BgpMessage, probe_bgp};
use crate::layer::application::dns::{DnsMessage, probe_dns_over_tcp};
use crate::layer::application::http::{HttpMessage, probe_http};
use crate::layer::application::ldap::{LdapMessage, probe_ldap};
use crate::layer::application::mqtt::{MqttMessage, probe_mqtt};
use crate::layer::application::smb1::{Smb1Header, probe_smb1};
use crate::layer::application::smb2::{Smb2Header, probe_smb2};
use crate::layer::application::tls::{TlsClientHello, probe_tls_client_hello};
use crate::layer::transport::tcp::TcpHeader;

const DEFAULT_MAX_PROBE_BYTES: usize = 65_536;
const DEFAULT_MAX_PROBE_FLOWS: usize = 65_536;
const DEFAULT_MAX_TOTAL_PROBE_BYTES: usize = 64 * 1_048_576;

/// Application message recognized in a reassembled TCP stream.
///
/// Non-exhaustive: a protocol added here should not break a caller that
/// matches on the ones it knows.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StreamL7 {
    /// An HTTP/1.x request or response.
    Http(HttpMessage),
    /// A TLS ClientHello.
    Tls(TlsClientHello),
    /// A BGP message, identified by its marker.
    Bgp(BgpMessage),
    /// An SMB2 header, past the direct-TCP length prefix.
    Smb2(Smb2Header),
    /// An SMB1 header, past the direct-TCP length prefix.
    Smb1(Smb1Header),
    /// An LDAP message.
    Ldap(LdapMessage),
    /// A DNS message carried over TCP, past its two-byte length prefix.
    Dns(DnsMessage),
    /// An MQTT control packet.
    Mqtt(MqttMessage),
}

/// Message recognized in one TCP flow direction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamEvent {
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub l7: StreamL7,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DirectionKey {
    flow: BiFlow,
    direction: usize,
}

#[derive(Debug, Default)]
struct ProbeState {
    bytes: Vec<u8>,
    done: bool,
    last_seen: LastSeen,
}

/// What a [`SessionTracker`] is holding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct SessionStats {
    /// Directions currently being probed.
    pub active_probes: usize,
    /// Bytes held across every probe.
    pub probe_bytes: usize,
    /// Unfinished probes dropped to make room under the global byte cap.
    pub probe_evictions: u64,
    /// Directions retired because they reached a cap while still undecided.
    pub probe_resource_limits: u64,
    /// The TCP reassembly underneath.
    pub tcp: TcpReassemblyStats,
}

/// Reassembles TCP payloads and probes each direction once for HTTP or TLS.
#[derive(Debug)]
pub struct SessionTracker {
    tcp: TcpStreamReassembler,
    probes: HashMap<DirectionKey, ProbeState>,
    generations: HashMap<BiFlow, u64>,
    max_probe_bytes: usize,
    max_probe_flows: usize,
    max_total_probe_bytes: usize,
    total_probe_bytes: usize,
    probe_evictions: u64,
    probe_resource_limits: u64,
    insertion_order: VecDeque<DirectionKey>,
    /// Probes holding bytes, oldest first. Stale entries are dropped as they
    /// reach the front.
    holding: VecDeque<DirectionKey>,
}

impl SessionTracker {
    /// Uses a 65,536-byte application probe cap per direction.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_PROBE_BYTES)
    }

    /// Uses the given application probe cap per direction.
    #[must_use]
    pub fn with_limits(max_probe_bytes: usize) -> Self {
        Self {
            tcp: TcpStreamReassembler::new(),
            probes: HashMap::new(),
            generations: HashMap::new(),
            max_probe_bytes,
            max_probe_flows: DEFAULT_MAX_PROBE_FLOWS,
            max_total_probe_bytes: DEFAULT_MAX_TOTAL_PROBE_BYTES,
            total_probe_bytes: 0,
            probe_evictions: 0,
            probe_resource_limits: 0,
            insertion_order: VecDeque::new(),
            holding: VecDeque::new(),
        }
    }

    /// Sets the concurrent probe-direction limit.
    #[must_use]
    pub fn with_max_probe_flows(mut self, max_probe_flows: usize) -> Self {
        self.max_probe_flows = max_probe_flows;
        self
    }

    /// Sets the total probe-byte cap across every direction combined -
    /// `max_probe_bytes` alone only bounds one direction. Defaults to 64 MiB.
    #[must_use]
    pub fn with_max_total_probe_bytes(mut self, max_total_probe_bytes: usize) -> Self {
        self.max_total_probe_bytes = max_total_probe_bytes;
        self
    }

    /// Bytes currently held for in-progress probes across every direction.
    #[must_use]
    pub fn probe_bytes(&self) -> usize {
        self.total_probe_bytes
    }

    /// Returns the first HTTP or TLS message found in the frame's direction.
    /// What this tracker is holding, including the TCP reassembly under it.
    #[must_use]
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            active_probes: self.probes.len(),
            probe_bytes: self.total_probe_bytes,
            probe_evictions: self.probe_evictions,
            probe_resource_limits: self.probe_resource_limits,
            tcp: self.tcp.stats(),
        }
    }

    pub fn offer_frame(&mut self, raw: &[u8]) -> Option<StreamEvent> {
        self.offer_frame_inner(raw, None)
    }

    /// As [`Self::offer_frame`], dating the flow so [`Self::expire_before`] can
    /// age it out. Pass the packet's own timestamp when replaying a capture.
    pub fn offer_frame_at(&mut self, raw: &[u8], now: Timestamp) -> Option<StreamEvent> {
        self.offer_frame_inner(raw, Some(now))
    }

    /// Drop every dated probe last seen before `cutoff`, and expire the TCP
    /// reassembly under it. Returns how many probe directions went.
    pub fn expire_before(&mut self, cutoff: Timestamp) -> usize {
        let before = self.probes.len();
        let total = &mut self.total_probe_bytes;
        self.probes.retain(|_, probe| {
            if probe.last_seen.is_before(cutoff) {
                *total = total.saturating_sub(probe.bytes.len());
                false
            } else {
                true
            }
        });

        // The queue and the generations have to follow, or an expired key stays
        // queued: the same flow comes back, gets queued again, and the eviction
        // that pops the stale entry removes the live probe instead. The
        // reassemblers rebuild theirs after expiry for the same reason.
        let probes = &self.probes;
        self.insertion_order.retain(|key| probes.contains_key(key));
        self.generations
            .retain(|flow, _| probes.keys().any(|key| &key.flow == flow));

        self.tcp.expire_before(cutoff);
        before - self.probes.len()
    }

    /// Make sure a probe exists for this direction and is the current TCP
    /// generation, dating it when the caller supplied a clock.
    ///
    /// A new SYN on the same tuple starts a new generation, and the probe from
    /// the old connection must not carry over into it.
    fn probe_state_for(
        &mut self,
        key: &DirectionKey,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        now: Option<Timestamp>,
    ) -> Option<()> {
        let generation = self.tcp.generation(src, src_port, dst, dst_port)?;
        if self.generations.get(&key.flow).copied() != Some(generation) {
            self.remove_probe_flow(&key.flow);
        }

        if !self.probes.contains_key(key) {
            if self.max_probe_flows == 0 {
                return None;
            }
            self.evict_until_room();
            self.probes.insert(key.clone(), ProbeState::default());
            self.insertion_order.push_back(key.clone());
        }
        self.generations.insert(key.flow, generation);

        if let Some(now) = now
            && let Some(state) = self.probes.get_mut(key)
        {
            state.last_seen.observe(now);
        }

        Some(())
    }

    fn offer_frame_inner(&mut self, raw: &[u8], now: Option<Timestamp>) -> Option<StreamEvent> {
        let parsed = BuiltinPacketParser::parse(raw).ok()?;
        let (src, dst) = ip_endpoints(&parsed)?;
        let tcp = match parsed.transport.as_ref()? {
            TransportSegment::Tcp(tcp) => tcp,
            TransportSegment::Udp(_) | TransportSegment::Sctp(_) => return None,
        };
        let payload = tcp_payload(raw, &parsed, tcp)?;
        let src_port = tcp.source_port;
        let dst_port = tcp.destination_port;
        let key = direction_key(src, src_port, dst, dst_port);

        let contiguous = self.tcp.offer_inner(
            src,
            src_port,
            dst,
            dst_port,
            tcp.sequence_number,
            tcp.flags.syn,
            tcp.flags.fin,
            tcp.flags.rst,
            payload,
            now,
        );
        let contiguous = contiguous.data;

        if tcp.flags.rst {
            // TCP state for this flow is already gone; drop application probe
            // state for both directions too, or a stale ProbeState (done or
            // partial bytes) survives into the next connection on this tuple.
            self.remove_flow(src, src_port, dst, dst_port);
            return None;
        }

        self.probe_state_for(&key, src, src_port, dst, dst_port, now)?;
        let state = self.probes.get_mut(&key)?;
        if state.done {
            return None;
        }
        let wanted = contiguous.len();
        // Make room globally before appending, so one direction sitting on the
        // budget cannot stop every later stream from being classified.
        self.make_room_for(&key, wanted);
        let state = self.probes.get_mut(&key)?;

        let per_direction_remaining = self.max_probe_bytes.saturating_sub(state.bytes.len());
        let total_remaining = self
            .max_total_probe_bytes
            .saturating_sub(self.total_probe_bytes);
        let append_len = per_direction_remaining.min(total_remaining).min(wanted);
        let mut newly_holding = false;
        if let Some(bytes) = contiguous.get(..append_len)
            && !bytes.is_empty()
        {
            newly_holding = state.bytes.is_empty();
            state.bytes.extend_from_slice(bytes);
            self.total_probe_bytes = self.total_probe_bytes.saturating_add(bytes.len());
        }
        if newly_holding {
            // A direct field, so this does not disturb the borrow on `probes`
            // that the rest of this function still holds.
            self.holding.push_back(key.clone());
        }
        // Either cap can stop a direction making progress: its own, or the
        // global one refusing bytes that nothing could be evicted to fit.
        let starved = append_len < wanted;
        let at_a_cap = state.bytes.len() >= self.max_probe_bytes || starved;

        // A direction that is finished with, matched or not, gives its buffer
        // back. Holding bytes for a stream no protocol can ever claim is how
        // the global probe budget fills up and stops classifying everything
        // else.
        let l7 = match classify_stream(&state.bytes) {
            StreamProbeState::NeedMore => {
                // Still undecided with no room left to decide in. Retiring it
                // is the honest outcome: a cap should degrade predictably, not
                // leave a direction buffering forever.
                if at_a_cap {
                    Self::retire_probe(state, &mut self.total_probe_bytes);
                    self.probe_resource_limits = self.probe_resource_limits.saturating_add(1);
                }
                return None;
            }
            StreamProbeState::Terminal => {
                Self::retire_probe(state, &mut self.total_probe_bytes);
                return None;
            }
            StreamProbeState::Match(l7) => *l7,
        };
        Self::retire_probe(state, &mut self.total_probe_bytes);
        Some(StreamEvent {
            src,
            src_port,
            dst,
            dst_port,
            l7,
        })
    }

    /// Drops the oldest unfinished probes until `wanted` bytes fit under the
    /// global cap, leaving `keep` alone.
    fn prune_holding(&mut self) {
        if self.holding.len() <= self.max_probe_flows.saturating_mul(2) {
            return;
        }
        let probes = &self.probes;
        self.holding.retain(|key| {
            probes
                .get(key)
                .is_some_and(|state| !state.done && !state.bytes.is_empty())
        });
    }

    fn make_room_for(&mut self, keep: &DirectionKey, wanted: usize) {
        self.prune_holding();

        // `keep` is the reason for the append, so it is passed over rather than
        // reclaimed. Held aside and put back, so passing it does not spin.
        let mut passed = Vec::new();

        while self.total_probe_bytes.saturating_add(wanted) > self.max_total_probe_bytes {
            let Some(candidate) = self.holding.pop_front() else {
                break;
            };
            if &candidate == keep {
                passed.push(candidate);
                continue;
            }
            // Only an unfinished probe is holding bytes worth taking. A done
            // direction holds none, and removing it would let the stream be
            let Some(state) = self.probes.get_mut(&candidate) else {
                continue;
            };
            if state.done || state.bytes.is_empty() {
                continue;
            }
            // Retired in place, not removed: the entry stays as a tombstone so
            // the direction is not probed again from the middle.
            Self::retire_probe(state, &mut self.total_probe_bytes);
            self.probe_evictions = self.probe_evictions.saturating_add(1);
        }

        for key in passed {
            self.holding.push_front(key);
        }
    }

    /// Marks a direction done and releases the bytes it was holding.
    fn retire_probe(state: &mut ProbeState, total_probe_bytes: &mut usize) {
        state.done = true;
        *total_probe_bytes = total_probe_bytes.saturating_sub(state.bytes.len());
        state.bytes.clear();
        state.bytes.shrink_to_fit();
    }

    /// Removes both directions of a flow, returning whether any state existed.
    pub fn remove_flow(&mut self, src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> bool {
        let flow = normalized_flow(src, src_port, dst, dst_port);
        let probes_removed = self.remove_probe_flow(&flow);
        let generation_removed = self.generations.remove(&flow).is_some();
        self.tcp.remove_flow(src, src_port, dst, dst_port) || probes_removed || generation_removed
    }

    fn remove_probe_flow(&mut self, flow: &BiFlow) -> bool {
        let previous_len = self.probes.len();
        let mut freed = 0usize;
        self.probes.retain(|key, state| {
            let keep = &key.flow != flow;
            if !keep {
                freed = freed.saturating_add(state.bytes.len());
            }
            keep
        });
        self.total_probe_bytes = self.total_probe_bytes.saturating_sub(freed);
        self.insertion_order.retain(|key| &key.flow != flow);
        self.probes.len() != previous_len
    }

    /// Releases all TCP and application probe state.
    pub fn clear(&mut self) {
        self.tcp.clear();
        self.probes.clear();
        self.generations.clear();
        self.insertion_order.clear();
        self.holding.clear();
        self.total_probe_bytes = 0;
    }

    fn evict_until_room(&mut self) {
        while self.probes.len() >= self.max_probe_flows {
            let Some(oldest) = self.insertion_order.pop_front() else {
                self.probes.clear();
                self.total_probe_bytes = 0;
                break;
            };
            if let Some(state) = self.probes.remove(&oldest) {
                self.total_probe_bytes = self.total_probe_bytes.saturating_sub(state.bytes.len());
            }

            // Clear stale TCP sequence state after both probe directions are gone.
            let flow = &oldest.flow;
            let other_direction = DirectionKey {
                flow: *flow,
                direction: 1 - oldest.direction,
            };
            if !self.probes.contains_key(&other_direction) {
                self.tcp.remove_flow(
                    flow.first.address,
                    flow.first.port,
                    flow.second.address,
                    flow.second.port,
                );
                self.generations.remove(flow);
            }
        }
    }
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn ip_endpoints(parsed: &ParsedPacket) -> Option<(IpAddr, IpAddr)> {
    if let Some(ipv4) = parsed.ipv4.as_ref() {
        Some((IpAddr::V4(ipv4.source), IpAddr::V4(ipv4.destination)))
    } else {
        parsed
            .ipv6
            .as_ref()
            .map(|ipv6| (IpAddr::V6(ipv6.source), IpAddr::V6(ipv6.destination)))
    }
}

/// Where the TCP payload sits in the frame the caller handed over.
///
/// `payload_offset` is right for every link type: a raw IP capture gets a
/// synthetic link header with an offset of zero, and a cooked one gets its
/// real 16-byte offset. See `looks_like_bare_ip`.
fn tcp_payload<'a>(raw: &'a [u8], parsed: &ParsedPacket, tcp: &TcpHeader) -> Option<&'a [u8]> {
    let l3_offset = parsed.ethernet.as_ref()?.payload_offset;
    let (ip_header_len, ip_packet_len) = if let Some(ipv4) = parsed.ipv4.as_ref() {
        (
            usize::from(ipv4.ihl).checked_mul(4)?,
            usize::from(ipv4.total_length),
        )
    } else {
        let ipv6 = parsed.ipv6.as_ref()?;
        (
            usize::from(ipv6.transport_header_offset),
            40usize.checked_add(usize::from(ipv6.payload_length))?,
        )
    };
    let ip_end = l3_offset.checked_add(ip_packet_len)?.min(raw.len());
    let tcp_offset = l3_offset.checked_add(ip_header_len)?;
    let tcp_header_len = usize::from(tcp.data_offset).checked_mul(4)?;
    let payload_offset = tcp_offset.checked_add(tcp_header_len)?;
    raw.get(payload_offset..ip_end)
}

/// Classify what a stream is carrying, once enough of it has arrived.
///
/// The probes own the framing rules, so this does not repeat them. `Incomplete`
/// means the stream may still become this protocol and the caller keeps
/// buffering; `Malformed` means it claimed to be and was not, so nothing else
/// is tried.
/// What the classifier concluded about a direction's bytes so far.
enum StreamProbeState {
    Match(Box<StreamL7>),
    /// A protocol is identified but its message is not complete, or nothing has
    /// ruled the remaining candidates out yet. Keep buffering.
    NeedMore,
    /// No protocol can ever match these bytes. The buffer can go.
    Terminal,
}

/// Whether an `Incomplete` from this probe means "this is mine, but short".
///
/// A probe that has matched a signature owns the stream, and trying a weaker
/// protocol on the same prefix is how a stream gets misidentified. A probe that
/// has only read a length field owns nothing: DNS-over-TCP reads MQTT's
/// `10 0c` as a 4108-byte message and would otherwise shadow it, and LDAP's
/// lone `0x30` tag is also MQTT PUBLISH's first byte.
type Committed = fn(&[u8]) -> bool;

fn tls_committed(bytes: &[u8]) -> bool {
    // Content type and version, per RFC 8446 sec 5.1.
    bytes.len() >= 3
}

fn http_committed(bytes: &[u8]) -> bool {
    // Enough for the shortest method plus its space.
    bytes.len() >= 4
}

fn bgp_committed(bytes: &[u8]) -> bool {
    // The whole marker, per RFC 4271 sec 4.1.
    bytes.len() >= 16
}

fn smb_committed(bytes: &[u8]) -> bool {
    // The direct-TCP prefix and the protocol id behind it.
    bytes.len() >= 8
}

fn never_committed(_: &[u8]) -> bool {
    false
}

/// What a probe that did not match means for the rest of the walk.
enum Step {
    /// This probe owns the stream and has decided for it.
    Stop(StreamProbeState),
    /// It cannot decide and has no claim, so the next protocol still might.
    Undecided,
    /// Ruled out.
    Next,
}

fn step_after<T>(result: &ProbeResult<T>, bytes: &[u8], committed: Committed) -> Step {
    match result {
        // Only a probe that matched a signature has standing to call the
        // stream broken, or to hold it while the rest arrives. LDAP reports
        // malformed off a lone 0x30, which is also MQTT PUBLISH's first byte.
        ProbeResult::Malformed(_) if committed(bytes) => Step::Stop(StreamProbeState::Terminal),
        ProbeResult::Incomplete { .. } if committed(bytes) => {
            Step::Stop(StreamProbeState::NeedMore)
        }
        ProbeResult::Incomplete { .. } => Step::Undecided,
        ProbeResult::Match(_) | ProbeResult::Malformed(_) | ProbeResult::NoMatch => Step::Next,
    }
}

/// Tries each protocol against the bytes reassembled so far, strongest
/// signature first. MQTT is last: a control packet is little more than a type
/// nibble and a length.
fn classify_stream(bytes: &[u8]) -> StreamProbeState {
    macro_rules! walk {
        ($($probe:expr, $variant:expr, $committed:expr;)*) => {{
            let mut waiting = false;
            $(
                match $probe {
                    ProbeResult::Match(value) => {
                        return StreamProbeState::Match(Box::new($variant(value)));
                    }
                    other => match step_after(&other, bytes, $committed) {
                        Step::Stop(state) => return state,
                        Step::Undecided => waiting = true,
                        Step::Next => {}
                    },
                }
            )*
            if waiting {
                StreamProbeState::NeedMore
            } else {
                StreamProbeState::Terminal
            }
        }};
    }

    walk! {
        probe_tls_client_hello(bytes), StreamL7::Tls, tls_committed;
        probe_http(bytes), StreamL7::Http, http_committed;
        probe_bgp(bytes), StreamL7::Bgp, bgp_committed;
        probe_smb2(bytes), StreamL7::Smb2, smb_committed;
        probe_smb1(bytes), StreamL7::Smb1, smb_committed;
        probe_ldap(bytes), StreamL7::Ldap, never_committed;
        probe_dns_over_tcp(bytes), StreamL7::Dns, never_committed;
        probe_mqtt(bytes), StreamL7::Mqtt, never_committed;
    }
}

fn direction_key(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> DirectionKey {
    let (flow, direction) = BiFlow::normalize(src, src_port, dst, dst_port);
    DirectionKey {
        flow,
        direction: direction.index(),
    }
}

fn normalized_flow(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> BiFlow {
    direction_key(src, src_port, dst, dst_port).flow
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const SRC_PORT: u16 = 49_152;
    const DST_PORT: u16 = 443;

    fn tcp_frame(src_port: u16, sequence: u32, syn: bool, payload: &[u8]) -> Vec<u8> {
        let tcp_len = 20usize.saturating_add(payload.len());
        let ip_len = 20usize.saturating_add(tcp_len);
        let ip_len = u16::try_from(ip_len).unwrap_or(u16::MAX);
        let mut frame = Vec::with_capacity(14 + usize::from(ip_len));
        frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        frame.extend_from_slice(&[0x45, 0]);
        frame.extend_from_slice(&ip_len.to_be_bytes());
        frame.extend_from_slice(&0x1234u16.to_be_bytes());
        frame.extend_from_slice(&0x4000u16.to_be_bytes());
        frame.extend_from_slice(&[64, 6, 0, 0]);
        frame.extend_from_slice(&[10, 0, 0, 1]);
        frame.extend_from_slice(&[10, 0, 0, 2]);

        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&DST_PORT.to_be_bytes());
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.push(0x50);
        frame.push(if syn { 0x02 } else { 0x18 });
        frame.extend_from_slice(&0x4000u16.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.extend_from_slice(payload);
        frame
    }

    fn tcp_rst_frame(src_port: u16, sequence: u32) -> Vec<u8> {
        let mut frame = tcp_frame(src_port, sequence, false, &[]);
        let flags_offset = 14 + 20 + 13; // Ethernet + IPv4 header + TCP flags byte
        frame[flags_offset] = 0x04;
        frame
    }

    fn ipv6_hop_by_hop_tcp_frame(payload: &[u8]) -> Vec<u8> {
        // Hop-by-Hop (next_header=0) wrapping TCP: next_header=6, hdr_ext_len=0
        // (8-byte ext header), then a minimal TCP header, then payload.
        let hop_by_hop = [6u8, 0, 0, 0, 0, 0, 0, 0];
        let tcp_len = 20usize + payload.len();
        let l4_len = hop_by_hop.len() + tcp_len;
        let mut frame = Vec::with_capacity(14 + 40 + l4_len);
        frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        frame.extend_from_slice(&0x86ddu16.to_be_bytes());

        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&u16::try_from(l4_len).unwrap_or(u16::MAX).to_be_bytes());
        frame.push(0); // next_header: Hop-by-Hop
        frame.push(64);
        frame.extend_from_slice(&[0; 15]);
        frame.push(1);
        frame.extend_from_slice(&[0; 15]);
        frame.push(2);

        frame.extend_from_slice(&hop_by_hop);

        frame.extend_from_slice(&SRC_PORT.to_be_bytes());
        frame.extend_from_slice(&DST_PORT.to_be_bytes());
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.push(0x50);
        frame.push(0x18);
        frame.extend_from_slice(&0x4000u16.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn tcp_payload_locates_data_past_ipv6_hop_by_hop_extension_header() {
        let payload = b"hello";
        let frame = ipv6_hop_by_hop_tcp_frame(payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let Some(TransportSegment::Tcp(tcp)) = parsed.transport.as_ref() else {
            panic!("expected TCP transport");
        };

        let found = tcp_payload(&frame, &parsed, tcp).expect("payload should be located");
        assert_eq!(found, payload);
    }

    fn tls_client_hello() -> Vec<u8> {
        let server_name = b"example.com";
        let server_name_list_len = 3usize.saturating_add(server_name.len());
        let extension_data_len = 2usize.saturating_add(server_name_list_len);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(
            &u16::try_from(extension_data_len)
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        extensions.extend_from_slice(
            &u16::try_from(server_name_list_len)
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        extensions.push(0);
        extensions.extend_from_slice(
            &u16::try_from(server_name.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        extensions.extend_from_slice(server_name);

        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[0x42; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&0x1301u16.to_be_bytes());
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(
            &u16::try_from(extensions.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        hello.extend_from_slice(&extensions);

        let handshake_len = u32::try_from(hello.len()).unwrap_or(u32::MAX);
        let handshake_len_bytes = handshake_len.to_be_bytes();
        let record_len = 4usize.saturating_add(hello.len());
        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&u16::try_from(record_len).unwrap_or(u16::MAX).to_be_bytes());
        record.push(1);
        record.extend_from_slice(&handshake_len_bytes[1..]);
        record.extend_from_slice(&hello);
        record
    }

    #[test]
    fn parses_http_across_tcp_segments() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let split = 12;
        let first = tcp_frame(SRC_PORT, 1_000, false, &payload[..split]);
        let second = tcp_frame(
            SRC_PORT,
            1_000u32.saturating_add(u32::try_from(split).unwrap_or(u32::MAX)),
            false,
            &payload[split..],
        );
        let mut tracker = SessionTracker::new();

        assert!(tracker.offer_frame(&first).is_none());
        let event = tracker.offer_frame(&second).expect("HTTP stream event");
        match event.l7 {
            StreamL7::Http(HttpMessage::Request { target, host, .. }) => {
                assert_eq!(target, "/index.html");
                assert_eq!(host.as_deref(), Some("example.com"));
            }
            _ => panic!("expected HTTP request"),
        }
    }

    #[test]
    fn rst_clears_probe_state_so_next_connection_starts_fresh() {
        let mut tracker = SessionTracker::new();

        // First connection: probe completes (state.done = true).
        let first_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let event = tracker
            .offer_frame(&tcp_frame(SRC_PORT, 1_000, false, first_payload))
            .expect("HTTP stream event");
        assert!(matches!(
            event.l7,
            StreamL7::Http(HttpMessage::Request { .. })
        ));

        assert!(
            tracker
                .offer_frame(&tcp_rst_frame(SRC_PORT, 2_000))
                .is_none()
        );

        // A fresh connection on the same 4-tuple must be probed again, not
        // silently dropped by a stale `done` flag from before the RST.
        let second_payload = b"GET /other.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let event = tracker
            .offer_frame(&tcp_frame(SRC_PORT, 3_000, false, second_payload))
            .expect("HTTP stream event after RST should be probed fresh");
        match event.l7 {
            StreamL7::Http(HttpMessage::Request { target, .. }) => {
                assert_eq!(target, "/other.html");
            }
            _ => panic!("expected HTTP request"),
        }
    }

    #[test]
    fn syn_restart_clears_probe_state_so_next_connection_starts_fresh() {
        let mut tracker = SessionTracker::new();

        let first_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let event = tracker
            .offer_frame(&tcp_frame(SRC_PORT, 1_000, false, first_payload))
            .expect("HTTP stream event");
        assert!(matches!(
            event.l7,
            StreamL7::Http(HttpMessage::Request { .. })
        ));

        assert!(
            tracker
                .offer_frame(&tcp_frame(SRC_PORT, 3_000, true, &[]))
                .is_none()
        );

        let second_payload = b"GET /other.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let event = tracker
            .offer_frame(&tcp_frame(SRC_PORT, 3_001, false, second_payload))
            .expect("HTTP stream event after SYN restart should be probed fresh");
        match event.l7 {
            StreamL7::Http(HttpMessage::Request { target, .. }) => {
                assert_eq!(target, "/other.html");
            }
            _ => panic!("expected HTTP request"),
        }
    }

    /// The global cap is shared, so pressure evicts the oldest unfinished
    /// probe rather than truncating the newest. Truncating leaves a direction
    /// that can never decide.
    #[test]
    fn global_pressure_evicts_the_oldest_probe() {
        let mut tracker = SessionTracker::new().with_max_total_probe_bytes(10);

        assert!(
            tracker
                .offer_frame(&tcp_frame(SRC_PORT, 1_000, false, b"GET /a"))
                .is_none()
        );
        assert_eq!(tracker.probe_bytes(), 6);

        // A second flow needs room the first is holding.
        assert!(
            tracker
                .offer_frame(&tcp_frame(2_000, 1_000, false, b"GET /b"))
                .is_none()
        );
        assert_eq!(
            tracker.probe_bytes(),
            6,
            "the newest probe holds its bytes whole"
        );
        assert_eq!(tracker.stats().probe_evictions, 1);
    }

    /// The case that matters: a flow sitting on the budget must not stop a
    /// later, immediately recognisable stream from being classified.
    #[test]
    fn pressure_does_not_stop_a_later_stream_from_classifying() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        // Exactly enough for the request, so without eviction the four bytes
        // the first flow holds would truncate it out of recognition.
        let mut tracker = SessionTracker::new().with_max_total_probe_bytes(request.len());

        // A flow that will never decide, holding most of the budget.
        assert!(
            tracker
                .offer_frame(&tcp_frame(SRC_PORT, 1_000, false, b"GET "))
                .is_none()
        );

        let event = tracker.offer_frame(&tcp_frame(2_000, 1_000, false, request));
        assert!(
            event.is_some(),
            "a recognisable stream must still classify under pressure"
        );
    }

    #[test]
    fn a_stream_is_not_reclaimed_to_make_room_for_itself() {
        // Small enough that the third append is under pressure, and payload
        // that no probe will ever claim, so it accumulates instead of deciding.
        let mut tracker = SessionTracker::new().with_max_total_probe_bytes(16);

        let mut sequence = 1_000u32;
        for _ in 0..3 {
            tracker.offer_frame(&tcp_frame(SRC_PORT, sequence, false, &[0xAB; 8]));
            sequence = sequence.wrapping_add(8);
        }

        let stats = tracker.stats();
        assert_eq!(
            stats.probe_evictions, 0,
            "the only holder was the stream being appended to, so nothing was evicted"
        );
        assert_eq!(
            stats.probe_resource_limits, 1,
            "it should be given up as starved instead"
        );
    }

    /// The global cap can starve a direction that is nowhere near its own.
    /// With nothing to evict, appending fewer bytes than arrived means it can
    /// never decide, so it is retired rather than left buffering forever.
    #[test]
    fn a_direction_starved_by_the_global_cap_is_retired() {
        // Far below the per-direction cap, so only the global one can bite.
        let mut tracker = SessionTracker::new().with_max_total_probe_bytes(16);

        let mut record = vec![0x16, 0x03, 0x01, 0xff, 0x00];
        record.extend([0x42; 64]);
        assert!(
            tracker
                .offer_frame(&tcp_frame(SRC_PORT, 1_000, false, &record))
                .is_none()
        );

        assert_eq!(
            tracker.probe_bytes(),
            0,
            "a direction that cannot make progress holds nothing"
        );
        assert_eq!(tracker.stats().probe_resource_limits, 1);
    }

    /// A direction that already classified keeps a tombstone so it is not
    /// probed again from the middle of the connection. Byte pressure must not
    /// take that away: the tombstone holds no bytes, so there is nothing to
    /// gain and a mid-stream reclassification to lose.
    #[test]
    fn byte_pressure_does_not_remove_a_finished_direction() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut tracker = SessionTracker::new().with_max_total_probe_bytes(request.len());

        // Classify one direction, which leaves it done.
        assert!(
            tracker
                .offer_frame(&tcp_frame(SRC_PORT, 1_000, false, request))
                .is_some()
        );

        // An unfinished probe holding bytes, so there is something to evict.
        assert!(
            tracker
                .offer_frame(&tcp_frame(2_000, 1_000, false, b"GET "))
                .is_none()
        );
        // A third flow now forces the eviction loop to run.
        assert!(
            tracker
                .offer_frame(&tcp_frame(3_000, 1_000, false, request))
                .is_some()
        );
        assert!(
            tracker.stats().probe_evictions > 0,
            "the fixture must actually apply pressure"
        );

        // More bytes on the classified direction must not start a new probe
        // from the middle of its stream.
        let mid_stream = tracker.offer_frame(&tcp_frame(
            SRC_PORT,
            1_000 + u32::try_from(request.len()).expect("short"),
            false,
            request,
        ));
        assert!(
            mid_stream.is_none(),
            "a classified direction was probed again from the middle"
        );
    }

    /// A direction that reaches its own cap while still undecided is retired,
    /// not left buffering forever.
    #[test]
    fn a_direction_that_cannot_decide_within_its_cap_is_retired() {
        let mut tracker = SessionTracker::with_limits(16);

        // A TLS record header promising far more than the cap allows.
        let mut record = vec![0x16, 0x03, 0x01, 0xff, 0x00];
        record.extend([0x42; 32]);
        assert!(
            tracker
                .offer_frame(&tcp_frame(SRC_PORT, 1_000, false, &record))
                .is_none()
        );

        assert_eq!(
            tracker.probe_bytes(),
            0,
            "the direction gave its buffer back rather than pinning it"
        );
        assert_eq!(tracker.stats().probe_resource_limits, 1);
    }

    #[test]
    fn parses_tls_client_hello_across_tcp_segments() {
        let payload = tls_client_hello();
        let split = 12;
        let first = tcp_frame(SRC_PORT, 2_000, false, &payload[..split]);
        let second = tcp_frame(
            SRC_PORT,
            2_000u32.saturating_add(u32::try_from(split).unwrap_or(u32::MAX)),
            false,
            &payload[split..],
        );
        let mut tracker = SessionTracker::new();

        assert!(tracker.offer_frame(&first).is_none());
        let event = tracker.offer_frame(&second).expect("TLS stream event");
        match event.l7 {
            StreamL7::Tls(hello) => {
                assert_eq!(hello.server_name.as_deref(), Some("example.com"));
            }
            other => panic!("expected a TLS ClientHello, got {other:?}"),
        }
    }

    /// A BGP keepalive: sixteen marker bytes, then the length and type.
    fn bgp_keepalive() -> Vec<u8> {
        let mut message = vec![0xff; 16];
        message.extend(19u16.to_be_bytes());
        message.push(4);
        message
    }

    /// A DNS-over-TCP query for "a", behind its two-byte length prefix.
    fn dns_over_tcp_query() -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x01, 0x00];
        message.extend(1u16.to_be_bytes()); // one question
        message.extend([0, 0, 0, 0, 0, 0]); // no answers, authorities, extras
        message.extend([0x01, b'a', 0x00]); // qname "a"
        message.extend([0x00, 0x01, 0x00, 0x01]); // A, IN
        let mut framed = Vec::new();
        framed.extend(
            u16::try_from(message.len())
                .expect("short message")
                .to_be_bytes(),
        );
        framed.extend(message);
        framed
    }

    #[test]
    fn recognises_bgp_in_a_reassembled_stream() {
        let mut tracker = SessionTracker::new();
        tracker.offer_frame(&tcp_frame(SRC_PORT, 100, true, &[]));

        let event = tracker
            .offer_frame(&tcp_frame(SRC_PORT, 101, false, &bgp_keepalive()))
            .expect("a bgp keepalive is a stream event");
        match event.l7 {
            StreamL7::Bgp(message) => assert_eq!(message.length, 19),
            other => panic!("expected bgp, got {other:?}"),
        }
    }

    #[test]
    fn recognises_dns_over_tcp_in_a_reassembled_stream() {
        let mut tracker = SessionTracker::new();
        tracker.offer_frame(&tcp_frame(SRC_PORT, 100, true, &[]));

        let event = tracker
            .offer_frame(&tcp_frame(SRC_PORT, 101, false, &dns_over_tcp_query()))
            .expect("a dns query is a stream event");
        match event.l7 {
            StreamL7::Dns(message) => {
                assert_eq!(message.questions.len(), 1);
                assert_eq!(message.header.transaction_id, 0x1234);
            }
            other => panic!("expected dns, got {other:?}"),
        }
    }

    /// The length prefix arrives in one segment and the message in the next,
    /// which is the ordinary case for anything length-framed over TCP.
    #[test]
    fn a_dns_message_split_across_segments_is_recognised_once_whole() {
        let framed = dns_over_tcp_query();
        let mut tracker = SessionTracker::new();
        tracker.offer_frame(&tcp_frame(SRC_PORT, 100, true, &[]));

        assert!(
            tracker
                .offer_frame(&tcp_frame(SRC_PORT, 101, false, &framed[..6]))
                .is_none(),
            "an incomplete message must not be claimed by a weaker protocol"
        );
        let event = tracker
            .offer_frame(&tcp_frame(SRC_PORT, 101 + 6, false, &framed[6..]))
            .expect("the rest of the message completes it");
        assert!(matches!(event.l7, StreamL7::Dns(_)));
    }

    /// An MQTT CONNECT opens `10 0c`, which DNS-over-TCP reads as a 4108-byte
    /// message and reports incomplete. DNS has matched no signature there, only
    /// a length, so it must not stop the walk before MQTT is tried.
    #[test]
    fn a_length_prefix_guess_does_not_shadow_mqtt() {
        let mut connect = vec![0x10, 0x0c];
        connect.extend([0x00, 0x04]);
        connect.extend(b"MQTT");
        connect.extend([0x05, 0x02, 0x00, 0x3c, 0x00, 0x00, 0x00]);

        assert!(
            probe_dns_over_tcp(&connect).is_incomplete(),
            "the fixture must look incomplete to dns for this to test anything"
        );
        assert!(matches!(
            classify_stream(&connect),
            StreamProbeState::Match(_)
        ));
    }

    /// A QoS-0 MQTT PUBLISH opens `0x30`, which is also LDAP's BER SEQUENCE
    /// tag. One tag byte is not a signature.
    #[test]
    fn a_ber_tag_does_not_shadow_mqtt() {
        // A whole PUBLISH, so a Match proves mqtt was reached rather than the
        // walk merely ending up undecided.
        let mut publish = vec![0x30, 0x09];
        publish.extend([0x00, 0x05]);
        publish.extend(b"topic");
        publish.extend(b"hi");

        assert!(
            matches!(probe_ldap(&publish), ProbeResult::Malformed(_)),
            "the fixture must look malformed to ldap for this to test anything"
        );
        let state = classify_stream(&publish);
        assert!(
            matches!(state, StreamProbeState::Match(_)),
            "ldap's lone 0x30 stopped the walk before mqtt"
        );
    }

    /// A committed probe still owns the stream: TLS has matched a record
    /// header, so a weaker protocol must not be tried on the same prefix.
    #[test]
    fn a_committed_probe_still_stops_the_walk() {
        let partial_tls_record = [0x16u8, 0x03, 0x01, 0x02, 0x00];
        assert!(matches!(
            classify_stream(&partial_tls_record),
            StreamProbeState::NeedMore
        ));
    }

    /// Bytes no protocol can claim must not be held: the global probe budget
    /// is shared, and one dead stream holding its buffer costs every other.
    #[test]
    fn a_stream_no_protocol_claims_gives_its_buffer_back() {
        let mut tracker = SessionTracker::new();
        tracker.offer_frame(&tcp_frame(SRC_PORT, 100, true, &[]));

        // Long enough for every probe to have checked its signature: BGP
        // cannot rule itself out until its sixteen-byte marker has arrived, so
        // a shorter fixture is legitimately still undecided. The leading pair
        // is too small to be a DNS-over-TCP length.
        let junk = [
            0x00u8, 0x05, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];
        assert!(matches!(classify_stream(&junk), StreamProbeState::Terminal));

        assert!(
            tracker
                .offer_frame(&tcp_frame(SRC_PORT, 101, false, &junk))
                .is_none()
        );
        assert_eq!(
            tracker.probe_bytes(),
            0,
            "a terminal direction holds nothing"
        );
    }

    /// The first five bytes of a TLS record are also a well formed MQTT
    /// control packet: 0x16 is a PUBREL type nibble and 0x03 a remaining
    /// length. TLS reports `Incomplete` on them and MQTT reports `Match`, so
    /// the walk has to stop at the first `Incomplete` rather than carry on to
    /// a weaker protocol. Without that rule a ClientHello split across
    /// segments is reported as MQTT.
    #[test]
    fn an_incomplete_probe_stops_the_walk_before_a_weaker_one() {
        let partial_tls_record = [0x16u8, 0x03, 0x01, 0x02, 0x00];

        assert!(
            matches!(
                probe_tls_client_hello(&partial_tls_record),
                ProbeResult::Incomplete { .. }
            ),
            "the fixture must be an incomplete tls record for this to test anything"
        );
        assert!(
            matches!(probe_mqtt(&partial_tls_record), ProbeResult::Match(_)),
            "the fixture must also be a valid mqtt packet for this to test anything"
        );

        assert!(
            matches!(
                classify_stream(&partial_tls_record),
                StreamProbeState::NeedMore
            ),
            "a half-arrived tls record must not be reported as mqtt"
        );
    }

    /// MQTT is probed last precisely because its header is weak. HTTP text
    /// must never come back as an MQTT control packet.
    #[test]
    fn http_is_not_claimed_by_a_weaker_protocol() {
        let mut tracker = SessionTracker::new();
        tracker.offer_frame(&tcp_frame(SRC_PORT, 100, true, &[]));

        let event = tracker
            .offer_frame(&tcp_frame(
                SRC_PORT,
                101,
                false,
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            ))
            .expect("an http request is a stream event");
        assert!(matches!(event.l7, StreamL7::Http(_)), "got {:?}", event.l7);
    }

    /// Expiring a probe has to take its queue entry with it. Otherwise the
    /// same flow comes back, is queued a second time, and the eviction that
    /// pops the stale entry removes the live probe under that key - throwing
    /// out the newest flow while older ones survive.
    #[test]
    fn an_expired_probe_does_not_leave_its_queue_entry_behind() {
        let mut tracker = SessionTracker::new().with_max_probe_flows(3);
        let open_flow = |tracker: &mut SessionTracker, port: u16, now: Option<Timestamp>| {
            let syn = tcp_frame(port, 100, true, &[]);
            let data = tcp_frame(port, 101, false, b"GET ");
            match now {
                Some(now) => {
                    tracker.offer_frame_at(&syn, now);
                    tracker.offer_frame_at(&data, now);
                }
                None => {
                    tracker.offer_frame(&syn);
                    tracker.offer_frame(&data);
                }
            }
        };

        // A is dated, so it expires. B and C are undated and stay.
        open_flow(&mut tracker, SRC_PORT, Some(10));
        assert_eq!(tracker.expire_before(20), 1);

        open_flow(&mut tracker, SRC_PORT + 1, None);
        open_flow(&mut tracker, SRC_PORT + 2, None);

        // A comes back, and is now the newest of the three.
        open_flow(&mut tracker, SRC_PORT, None);
        assert_eq!(tracker.stats().active_probes, 3);

        // A fourth flow forces one eviction. It must take the oldest, not A.
        open_flow(&mut tracker, SRC_PORT + 3, None);

        let event = tracker.offer_frame(&tcp_frame(
            SRC_PORT,
            105,
            false,
            b"/ HTTP/1.1\r\nHost: a\r\n\r\n",
        ));
        assert!(
            event.is_some(),
            "the recreated probe was evicted by its own stale queue entry"
        );
    }

    /// The request bytes of `tcp_frame`, without its ethernet header.
    fn bare_ipv4_request() -> Vec<u8> {
        let framed = tcp_frame(SRC_PORT, 1_000, false, REQUEST);
        framed[14..].to_vec()
    }

    /// The same, behind a Linux cooked header instead.
    fn cooked_request() -> Vec<u8> {
        let mut frame = vec![0x00, 0x00];
        frame.extend([0x00, 0x01]);
        frame.extend([0x00, 0x06]);
        frame.extend([0, 1, 2, 3, 4, 5, 0x00, 0x00]);
        frame.extend([0x08, 0x00]);
        frame.extend(bare_ipv4_request());
        frame
    }

    const REQUEST: &[u8] = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

    /// The parser accepts a raw IP or cooked capture, so the tracker has to as
    /// well. Requiring an ethernet header made it silently see nothing.
    #[test]
    fn a_stream_is_tracked_without_an_ethernet_header() {
        for (label, frame) in [
            ("bare ipv4", bare_ipv4_request()),
            ("linux cooked", cooked_request()),
        ] {
            let mut tracker = SessionTracker::new();
            let event = tracker.offer_frame(&frame);
            let Some(event) = event else {
                panic!("{label} produced no stream event");
            };
            match event.l7 {
                StreamL7::Http(HttpMessage::Request { target, .. }) => {
                    assert_eq!(target, "/index.html", "{label}");
                }
                other => panic!("{label} gave {other:?}"),
            }
        }
    }

    #[test]
    fn parses_out_of_order_segments_after_syn() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let split = 12;
        let syn = tcp_frame(SRC_PORT, 999, true, &[]);
        let first = tcp_frame(SRC_PORT, 1_000, false, &payload[..split]);
        let second = tcp_frame(
            SRC_PORT,
            1_000u32.saturating_add(u32::try_from(split).unwrap_or(u32::MAX)),
            false,
            &payload[split..],
        );
        let mut tracker = SessionTracker::new();

        assert!(tracker.offer_frame(&syn).is_none());
        assert!(tracker.offer_frame(&second).is_none());
        let event = tracker
            .offer_frame(&first)
            .expect("out-of-order HTTP event");
        match event.l7 {
            StreamL7::Http(HttpMessage::Request { target, host, .. }) => {
                assert_eq!(target, "/index.html");
                assert_eq!(host.as_deref(), Some("example.com"));
            }
            _ => panic!("expected HTTP request"),
        }
    }

    #[test]
    fn probe_flow_count_is_bounded() {
        let mut tracker = SessionTracker::new().with_max_probe_flows(2);

        for src_port in [1_000, 1_001, 1_002, 1_003] {
            let frame = tcp_frame(src_port, 100, true, &[]);
            assert!(tracker.offer_frame(&frame).is_none());
            assert!(tracker.probes.len() <= 2);
        }
    }

    #[test]
    fn evicted_probe_flow_starts_with_fresh_state() {
        let mut tracker = SessionTracker::new().with_max_probe_flows(2);
        let prefix = tcp_frame(1_000, 100, false, b"G");
        assert!(tracker.offer_frame(&prefix).is_none());
        assert!(
            tracker
                .offer_frame(&tcp_frame(1_001, 200, true, &[]))
                .is_none()
        );
        assert!(
            tracker
                .offer_frame(&tcp_frame(1_002, 300, true, &[]))
                .is_none()
        );

        let continuation = b"ET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let resumed = tcp_frame(1_000, 101, false, continuation);
        assert!(tracker.offer_frame(&resumed).is_none());

        let key = direction_key(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1_000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            DST_PORT,
        );
        assert_eq!(
            tracker.probes.get(&key).map(|state| state.bytes.as_slice()),
            Some(continuation.as_slice())
        );
        assert_eq!(tracker.probes.len(), 2);
    }

    #[test]
    fn probe_eviction_also_clears_stale_tcp_sequence_state() {
        let mut tracker = SessionTracker::new().with_max_probe_flows(1);

        // Flow A: SYN only; its probe stays open.
        assert!(
            tracker
                .offer_frame(&tcp_frame(3_000, 500, true, &[]))
                .is_none()
        );
        // Flow B evicts A with max_probe_flows=1.
        assert!(
            tracker
                .offer_frame(&tcp_frame(3_001, 1, true, &[]))
                .is_none()
        );

        // Reuse the 4-tuple with an unrelated, distant sequence number.
        assert!(
            tracker
                .offer_frame(&tcp_frame(3_000, 50_000, true, &[]))
                .is_none()
        );
        let request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let event = tracker
            .offer_frame(&tcp_frame(3_000, 50_001, false, request))
            .expect("new connection's HTTP request should be recognized, not stuck behind stale seq state");
        match event.l7 {
            StreamL7::Http(HttpMessage::Request { target, .. }) => assert_eq!(target, "/"),
            _ => panic!("expected HTTP request"),
        }
    }
}
