use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpReassemblyEvent {
    InOrder(Vec<u8>),
    Gap { expected_seq: u32, got_seq: u32 },
    Duplicate { seq: u32 },
}

#[derive(Debug, Default)]
pub struct TcpStreamReassembler {
    next_seq: Option<u32>,
    buffered: BTreeMap<u32, Vec<u8>>,
}

impl TcpStreamReassembler {
    pub fn push(&mut self, seq: u32, payload: &[u8]) -> TcpReassemblyEvent {
        if payload.is_empty() {
            return TcpReassemblyEvent::InOrder(Vec::new());
        }

        let expected = match self.next_seq {
            Some(s) => s,
            None => {
                self.next_seq = Some(seq + payload.len() as u32);
                return TcpReassemblyEvent::InOrder(payload.to_vec());
            }
        };

        if seq < expected {
            return TcpReassemblyEvent::Duplicate { seq };
        }

        if seq > expected {
            self.buffered.insert(seq, payload.to_vec());
            return TcpReassemblyEvent::Gap {
                expected_seq: expected,
                got_seq: seq,
            };
        }

        let mut out = payload.to_vec();
        self.next_seq = Some(expected + payload.len() as u32);

        loop {
            let Some(next) = self.next_seq else {
                break;
            };
            let Some(chunk) = self.buffered.remove(&next) else {
                break;
            };
            self.next_seq = Some(next + chunk.len() as u32);
            out.extend_from_slice(&chunk);
        }

        TcpReassemblyEvent::InOrder(out)
    }
}
