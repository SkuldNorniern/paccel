pub fn is_expired(now_ms: u64, last_seen_ms: u64, ttl_ms: u64) -> bool {
    now_ms.saturating_sub(last_seen_ms) > ttl_ms
}

#[cfg(test)]
mod tests {
    use super::is_expired;

    #[test]
    fn expiry_logic_is_monotonic() {
        assert!(!is_expired(1_000, 900, 200));
        assert!(is_expired(1_000, 700, 200));
    }
}
